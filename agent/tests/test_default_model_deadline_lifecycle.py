"""Actual default model deadlines over in-memory ASGI; no provider or TCP.

The 25s production timer is never mocked, accelerated, or overridden. The
24.5..32s monotonic acceptance window allows CI scheduling overhead. A 40s
watchdog raises AssertionError outside the application, never TimeoutError.
This covers Python admission/model cancellation, not Java, DNS or HTTP pools.
"""
import asyncio
import time
from uuid import UUID

import httpx

from agent.app import create_app
from agent.dto import KycProposal
from agent.llm_adapter import ModelUnavailable
from agent.settings import Settings
from agent.tests.test_agent import HEADERS, PATH, TOKEN, rehash, request_body


def body_for(index):
    body = request_body()
    body['requestId'] = str(UUID(int=index))
    return rehash(body)


def proposal():
    return KycProposal(status='NOT_VERIFIED', evidenceIds=[], explanation='Synthetic lifecycle response')


class GateAdapter:
    model_name = 'synthetic-deadline-only'

    def __init__(self):
        self.entered = []
        self.cancelled = []
        self.cleaned = []
        self.active = set()
        self.peak = 0
        self.changed = asyncio.Event()
        self.release = asyncio.Event()
        self.fail = False

    async def propose(self, body):
        identity = str(body.requestId)
        self.entered.append((identity, time.monotonic()))
        self.active.add(identity)
        self.peak = max(self.peak, len(self.active))
        self.changed.set()
        try:
            if self.fail:
                raise ModelUnavailable('synthetic adapter failure')
            await self.release.wait()
            return proposal()
        except asyncio.CancelledError:
            self.cancelled.append(identity)
            raise
        finally:
            self.active.remove(identity)
            self.cleaned.append(identity)
            self.changed.set()


async def wait_until(predicate, changed):
    # Only setup/recovery observation; expiry always fails the test, not the API.
    end = time.monotonic() + 3
    while not predicate():
        remaining = end - time.monotonic()
        assert remaining > 0, 'Lifecycle observation did not occur'
        changed.clear()
        if predicate():
            return
        try:
            await asyncio.wait_for(changed.wait(), remaining)
        except TimeoutError as exc:
            raise AssertionError('Lifecycle observation watchdog expired') from exc


async def bounded(coroutine):
    try:
        return await asyncio.wait_for(coroutine, 40)
    except TimeoutError as exc:
        raise AssertionError('Test watchdog expired; not a model deadline success') from exc


def observe_semaphore(monkeypatch):
    # Delegate all behavior to the real semaphore; only observe blocked entries.
    real_semaphore = asyncio.Semaphore
    observed = []
    class ObservedSemaphore(real_semaphore):
        def __init__(self, value):
            super().__init__(value)
            self.waiting = asyncio.Event()
            self.queued_tasks = []
            observed.append(self)
        async def acquire(self):
            if self.locked():
                self.queued_tasks.append((asyncio.current_task(), time.monotonic()))
                self.waiting.set()
            return await super().acquire()
    monkeypatch.setattr('agent.app.asyncio.Semaphore', ObservedSemaphore)
    return observed


async def prove_full_recovery(client, adapter, semaphore):
    adapter.release.clear()
    recovered = [body_for(n) for n in range(101, 105)]
    identities = {body['requestId'] for body in recovered}
    queued_before = len(semaphore.queued_tasks)
    tasks = [asyncio.create_task(client.post(PATH, headers=HEADERS, json=body)) for body in recovered]
    try:
        await wait_until(lambda: adapter.active == identities, adapter.changed)
        assert adapter.peak == 4
        waiting_bodies = [body_for(n) for n in range(105, 109)]
        tasks.extend(asyncio.create_task(client.post(PATH, headers=HEADERS, json=body)) for body in waiting_bodies)
        await wait_until(lambda: len(semaphore.queued_tasks) == queued_before + 4, semaphore.waiting)
        assert adapter.active == identities
        assert not any(task.done() for task in tasks)
        entered_before = len(adapter.entered)
        denied = await client.post(PATH, headers=HEADERS, json=body_for(109))
        assert denied.status_code == 503
        assert denied.json() == {'decision': 'ERROR', 'reasonCode': 'DEPENDENCY_UNAVAILABLE'}
        assert len(adapter.entered) == entered_before
        recovered.extend(waiting_bodies)
        adapter.release.set()
        responses = await asyncio.gather(*tasks)
        for body, response in zip(recovered, responses):
            assert response.status_code == 200
            assert response.json()['requestId'] == body['requestId']
            assert response.json()['proposal']['status'] == 'NOT_VERIFIED'
        assert adapter.active == set()
        independent = body_for(200)
        response = await client.post(PATH, headers=HEADERS, json=independent)
        assert response.status_code == 200
        assert response.json()['requestId'] == independent['requestId']
        assert adapter.active == set()
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def test_default_model_deadline_cancels_active_and_queued_calls_and_recovers(monkeypatch):
    async def run():
        settings = Settings(service_token=TOKEN)
        assert settings.model_timeout_seconds == 25.0
        assert settings.max_parallel == 4
        adapter = GateAdapter()
        observed = observe_semaphore(monkeypatch)
        app = create_app(settings, adapter)
        assert len(observed) == 1
        starts, finishes = {}, {}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://in-memory.invalid') as client:
            async def post(index):
                body = body_for(index)
                starts[body['requestId']] = time.monotonic()
                response = await client.post(PATH, headers=HEADERS, json=body)
                finishes[body['requestId']] = time.monotonic()
                return response
            tasks = [asyncio.create_task(post(n)) for n in range(1, 5)]
            initial = {body_for(n)['requestId'] for n in range(1, 5)}
            fifth = body_for(5)['requestId']
            try:
                await wait_until(lambda: adapter.active == initial, adapter.changed)
                await asyncio.sleep(1)
                tasks.append(asyncio.create_task(post(5)))
                await wait_until(lambda: observed[0].waiting.is_set(), observed[0].waiting)
                assert adapter.active == initial
                assert len(adapter.entered) == 4
                assert len(observed[0].queued_tasks) == 1
                assert not adapter.release.is_set()
                responses = await asyncio.gather(*tasks)
                for response in responses:
                    assert response.status_code == 503
                    assert response.json() == {'decision': 'ERROR', 'reasonCode': 'DEPENDENCY_UNAVAILABLE'}
                expected = initial | {fifth}
                assert {identity for identity, _ in adapter.entered} == expected
                assert len(adapter.entered) == 5
                assert set(adapter.cancelled) == expected and len(adapter.cancelled) == 5
                assert set(adapter.cleaned) == expected and len(adapter.cleaned) == 5
                assert adapter.active == set() and adapter.peak == 4
                assert not adapter.release.is_set(), 'No normal release may cause deadline recovery'
                for identity in expected:
                    assert 24.5 <= finishes[identity] - starts[identity] <= 32
                fifth_entry = dict(adapter.entered)[fifth]
                assert fifth_entry - observed[0].queued_tasks[0][1] >= 23
                assert fifth_entry - starts[fifth] >= 23, 'Fifth must consume its deadline waiting'
                assert finishes[fifth] - fifth_entry < 4, 'Queue wait must not reset the model deadline'
                await prove_full_recovery(client, adapter, observed[0])
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run(bounded(run()))


def test_adapter_exception_releases_default_admission_capacity(monkeypatch):
    async def run():
        settings = Settings(service_token=TOKEN)
        assert settings.model_timeout_seconds == 25.0 and settings.max_parallel == 4
        adapter = GateAdapter()
        adapter.fail = True
        observed = observe_semaphore(monkeypatch)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(settings, adapter)),
                                     base_url='http://in-memory.invalid') as client:
            for index in range(1, 10):
                response = await client.post(PATH, headers=HEADERS, json=body_for(index))
                assert response.status_code == 503
                assert response.json() == {'decision': 'ERROR', 'reasonCode': 'DEPENDENCY_UNAVAILABLE'}
            assert len(adapter.entered) == len(adapter.cleaned) == 9
            assert not adapter.active and not adapter.cancelled
            adapter.fail = False
            await prove_full_recovery(client, adapter, observed[0])
    asyncio.run(bounded(run()))
