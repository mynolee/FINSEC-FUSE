"""Finite offline native-DNS tests. No provider, network I/O or subprocess.

Only socket.getaddrinfo is replaced; real native executor futures retain their
lifetime. Every test has a 14s watchdog; gated workers self-release after 8s.
"""
import asyncio
from concurrent.futures import Future
import signal
import socket
import sys
import threading
from unittest.mock import AsyncMock
import httpcore
import pytest
from agent import outbound

PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]
GUARD = {'active': False, 'blocked': []}

def audit(event, args):
    if not GUARD['active']: return
    forbidden = event in {'socket.connect', 'socket.bind', 'socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostbyaddr', 'socket.sendto', 'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork', 'os.exec'}
    if event == 'socket.__new__':
        forbidden = args[1] != socket.AF_UNIX or (args[2] & 15) != socket.SOCK_STREAM
    if forbidden:
        GUARD['blocked'].append(event)
        raise AssertionError('Offline DNS test attempted forbidden I/O')
sys.addaudithook(audit)

@pytest.fixture(autouse=True)
def offline_guard(monkeypatch):
    GUARD.update(active=True, blocked=[])
    def listen(*a, **kw):
        GUARD['blocked'].append('socket.listen')
        raise AssertionError('listen forbidden')
    monkeypatch.setattr(socket.socket, 'listen', listen)
    def deadline(*a): raise TimeoutError('DNS lifecycle 14-second watchdog')
    previous = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(14)
    try: yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        GUARD['active'] = False
        assert not GUARD['blocked']

class NativeGate:
    def __init__(self):
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.started = self.completed = self.active = self.peak = self.watchdog_releases = 0
        self.threads = set()
        self.error = False
    def __call__(self, host, port, **kwargs):
        assert (host, port, kwargs) == ('api.openai.com', 443, {'type': socket.SOCK_STREAM})
        with self.lock:
            self.threads.add(threading.current_thread())
            self.started += 1
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if not self.release.wait(8):
                with self.lock: self.watchdog_releases += 1
            if self.error: raise socket.gaierror('synthetic DNS error')
            return PUBLIC
        finally:
            with self.lock:
                self.completed += 1
                self.active -= 1

@pytest.fixture
def native(monkeypatch):
    gate, resolver = NativeGate(), outbound.BoundedResolver()
    monkeypatch.setattr(socket, 'getaddrinfo', gate)
    monkeypatch.setattr(outbound, '_MODEL_RESOLVER', resolver)
    try: yield gate, resolver
    finally:
        gate.release.set()
        resolver.close(wait=True)
        for thread in gate.threads: thread.join(timeout=1)
        assert gate.active == 0 and gate.completed == gate.started
        assert gate.watchdog_releases == 0
        assert all(not t.is_alive() for t in gate.threads)
        assert resolver._unfinished == 0

async def until(predicate):
    async with asyncio.timeout(2):
        while not predicate(): await asyncio.sleep(.001)

def test_timeouts_keep_four_native_slots_and_recover_through_dns(native, monkeypatch):
    gate, resolver = native
    tcp = AsyncMock(return_value='synthetic-stream')
    monkeypatch.setattr(outbound.AnyIOBackend, 'connect_tcp', tcp)
    async def run():
        diagnostics = []
        asyncio.get_running_loop().set_exception_handler(lambda _, ctx: diagnostics.append(ctx))
        tasks = [asyncio.create_task(outbound.PublicModelBackend().connect_tcp('api.openai.com', 443, .1)) for _ in range(4)]
        await until(lambda: gate.started == 4)
        assert all(isinstance(x, TimeoutError) for x in await asyncio.gather(*tasks, return_exceptions=True))
        assert gate.active == resolver._unfinished == 4
        for _ in range(40):
            with pytest.raises(httpcore.ConnectError):
                await outbound.PublicModelBackend().connect_tcp('api.openai.com', 443, .05)
        assert gate.started == gate.peak == resolver._unfinished == 4
        assert resolver._executor._work_queue.qsize() == 0 and tcp.await_count == 0
        gate.release.set()
        await until(lambda: resolver._unfinished == 0)
        assert await outbound.PublicModelBackend().connect_tcp('api.openai.com', 443, 1) == 'synthetic-stream'
        assert gate.started == gate.completed == 5
        assert tcp.await_count == 1 and tcp.call_args.args[0] == '8.8.8.8'
        await asyncio.sleep(0)
        assert not diagnostics
    asyncio.run(run())

@pytest.mark.parametrize('late_error', [False, True])
def test_cancellation_retains_slots_and_consumes_late_results(native, monkeypatch, late_error):
    gate, resolver = native
    gate.error = late_error
    tcp = AsyncMock(side_effect=AssertionError('abandoned request reached TCP'))
    monkeypatch.setattr(outbound.AnyIOBackend, 'connect_tcp', tcp)
    async def run():
        diagnostics = []
        asyncio.get_running_loop().set_exception_handler(lambda _, ctx: diagnostics.append(ctx))
        tasks = [asyncio.create_task(outbound.PublicModelBackend().connect_tcp('api.openai.com', 443, 2)) for _ in range(4)]
        await until(lambda: gate.started == 4)
        for task in tasks: task.cancel()
        assert all(isinstance(x, asyncio.CancelledError) for x in await asyncio.gather(*tasks, return_exceptions=True))
        for _ in range(30):
            task = asyncio.create_task(resolver.resolve('api.openai.com', 443))
            await asyncio.sleep(0)
            task.cancel()
            assert isinstance((await asyncio.gather(task, return_exceptions=True))[0], (httpcore.ConnectError, asyncio.CancelledError))
        assert gate.started == resolver._unfinished == 4
        assert resolver._executor._work_queue.qsize() == 0
        gate.release.set()
        await until(lambda: resolver._unfinished == 0)
        await asyncio.sleep(.01)
        assert not diagnostics and tcp.await_count == 0
        gate.error = False
        assert await resolver.resolve('api.openai.com', 443) == PUBLIC
    asyncio.run(run())

def test_distinct_closed_loops_share_default_process_capacity(native):
    gate, resolver = native
    failures = []
    def caller():
        async def run():
            with pytest.raises(TimeoutError):
                await outbound.PublicModelBackend().connect_tcp('api.openai.com', 443, .15)
        try: asyncio.run(run())
        except BaseException as exc: failures.append(exc)
    callers = [threading.Thread(target=caller) for _ in range(4)]
    try:
        for thread in callers: thread.start()
        for thread in callers: thread.join(timeout=2)
        assert not failures and all(not t.is_alive() for t in callers)
        assert gate.active == resolver._unfinished == 4
        async def rejected():
            for _ in range(20):
                with pytest.raises(httpcore.ConnectError):
                    await outbound.PublicModelBackend().connect_tcp('api.openai.com', 443, 1)
        asyncio.run(rejected())
        assert gate.started == 4
        gate.release.set()
        async def recover():
            await until(lambda: resolver._unfinished == 0)
            assert await resolver.resolve('api.openai.com', 443) == PUBLIC
        asyncio.run(recover())
    finally:
        gate.release.set()
        for thread in callers: thread.join(timeout=2)
        assert all(not t.is_alive() for t in callers)

class ManualExecutor:
    def __init__(self):
        self.futures = []
        self.fail = self.immediate = False
    def submit(self, *a, **kw):
        if self.fail: raise RuntimeError('synthetic submit failure')
        future = Future()
        self.futures.append(future)
        if self.immediate: future.set_result(PUBLIC)
        return future
    def shutdown(self, wait=False, cancel_futures=False):
        if cancel_futures:
            for future in self.futures: future.cancel()

def test_queued_submissions_stay_bounded_until_real_completion(monkeypatch):
    executor = ManualExecutor()
    monkeypatch.setattr(outbound, 'ThreadPoolExecutor', lambda **kw: executor)
    resolver = outbound.BoundedResolver()
    async def run():
        for _ in range(4):
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(.01): await resolver.resolve('api.openai.com', 443)
        assert len(executor.futures) == resolver._unfinished == 4
        assert all(not f.cancelled() for f in executor.futures)
        for _ in range(50):
            with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        assert len(executor.futures) == 4
        executor.futures[0].set_result(PUBLIC)
        assert resolver._unfinished == 3
        executor.immediate = True
        assert await resolver.resolve('api.openai.com', 443) == PUBLIC
        assert resolver._unfinished == 3
        resolver.close()
        assert resolver._unfinished == 0
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
    try: asyncio.run(run())
    finally: resolver.close(wait=True)

def test_submission_failure_is_terminal_without_retry(monkeypatch):
    executor = ManualExecutor()
    executor.fail = True
    monkeypatch.setattr(outbound, 'ThreadPoolExecutor', lambda **kw: executor)
    resolver = outbound.BoundedResolver(max_workers=1)
    async def run():
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        assert resolver._closed and resolver._unfinished == 1
        executor.fail, executor.immediate = False, True
        for _ in range(20):
            with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        assert not executor.futures
    try: asyncio.run(run())
    finally: resolver.close(wait=True)

def test_inline_completion_releases_exactly_once(monkeypatch):
    executor = ManualExecutor()
    executor.immediate = True
    monkeypatch.setattr(outbound, 'ThreadPoolExecutor', lambda **kw: executor)
    resolver = outbound.BoundedResolver(max_workers=1)
    async def run():
        for _ in range(20):
            assert await resolver.resolve('api.openai.com', 443) == PUBLIC
            assert resolver._unfinished == 0
    try: asyncio.run(run())
    finally: resolver.close(wait=True)


def test_close_running_native_is_terminal_without_early_release(native):
    gate, resolver = native
    async def run():
        task = asyncio.create_task(resolver.resolve('api.openai.com', 443))
        await until(lambda: gate.started == 1)
        resolver.close(wait=False)
        resolver.close(wait=False)
        assert gate.active == resolver._unfinished == 1
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        gate.release.set()
        assert await task == PUBLIC
        assert resolver._unfinished == 0
        resolver.close(wait=True)
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
    asyncio.run(run())

@pytest.mark.parametrize('capacity', [1, 2, 4])
def test_reduced_capacity_is_enforced_before_submission(monkeypatch, capacity):
    executor = ManualExecutor()
    monkeypatch.setattr(outbound, 'ThreadPoolExecutor', lambda **kw: executor)
    resolver = outbound.BoundedResolver(max_workers=capacity)
    async def run():
        tasks = [asyncio.create_task(resolver.resolve('api.openai.com', 443)) for _ in range(capacity)]
        await until(lambda: len(executor.futures) == capacity)
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        resolver.close()
        await asyncio.gather(*tasks, return_exceptions=True)
        assert resolver._unfinished == 0
    try: asyncio.run(run())
    finally: resolver.close(wait=True)

@pytest.mark.parametrize('records', [[], PUBLIC + [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))], [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 443, 0, 0))]])
def test_unsafe_dns_answers_fail_before_tcp(monkeypatch, records):
    resolver = type('Resolver', (), {'resolve': AsyncMock(return_value=records)})()
    tcp = AsyncMock(side_effect=AssertionError('unsafe DNS reached TCP'))
    monkeypatch.setattr(outbound.AnyIOBackend, 'connect_tcp', tcp)
    async def run():
        with pytest.raises(httpcore.ConnectError): await outbound.PublicModelBackend(resolver).connect_tcp('api.openai.com', 443, 1)
        assert tcp.await_count == 0
    asyncio.run(run())

@pytest.mark.parametrize('host,port', [('evil.invalid', 443), ('api.openai.com', 80), ('8.8.8.8', 443)])
def test_unregistered_destination_never_submits_dns(host, port):
    resolver = type('Resolver', (), {'resolve': AsyncMock(side_effect=AssertionError('unexpected DNS'))})()
    async def run():
        with pytest.raises(httpcore.ConnectError): await outbound.PublicModelBackend(resolver).connect_tcp(host, port, 1)
        assert resolver.resolve.await_count == 0
    asyncio.run(run())

def test_submit_start_then_raise_cannot_refill_uncertain_slot(monkeypatch):
    gate = NativeGate()
    threads = []
    class StartThenRaise:
        submissions = 0
        def submit(self, fn, *args, **kwargs):
            self.submissions += 1
            thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
            threads.append(thread)
            thread.start()
            raise RuntimeError('failure after enqueue/start')
        def shutdown(self, **kwargs): pass
    executor = StartThenRaise()
    monkeypatch.setattr(socket, 'getaddrinfo', gate)
    monkeypatch.setattr(outbound, 'ThreadPoolExecutor', lambda **kw: executor)
    resolver = outbound.BoundedResolver()
    async def run():
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        await until(lambda: gate.started == 1)
        for _ in range(30):
            with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        assert executor.submissions == resolver._unfinished == gate.active == 1
        assert resolver._closed
        gate.release.set()
        await until(lambda: gate.completed == 1)
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        assert executor.submissions == 1
    try: asyncio.run(run())
    finally:
        gate.release.set()
        resolver.close(wait=True)
        for thread in threads: thread.join(timeout=2)
        assert all(not t.is_alive() for t in threads)
        assert gate.watchdog_releases == gate.active == 0


def test_executor_construction_failure_is_terminal_with_no_native_reservation(monkeypatch):
    def fail(**kwargs): raise RuntimeError('constructor failure')
    monkeypatch.setattr(outbound, 'ThreadPoolExecutor', fail)
    resolver = outbound.BoundedResolver()
    async def run():
        for _ in range(2):
            with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        assert resolver._closed and resolver._unfinished == 0 and resolver._executor is None
    asyncio.run(run())


def test_native_error_releases_capacity_for_fresh_dns(native):
    gate, resolver = native
    gate.error = True
    gate.release.set()
    async def run():
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        assert resolver._unfinished == 0
        gate.error = False
        assert await resolver.resolve('api.openai.com', 443) == PUBLIC
        assert gate.started == gate.completed == 2
    asyncio.run(run())

@pytest.mark.parametrize('completion_first', [True, False])
def test_completion_cancel_order_never_double_releases(monkeypatch, completion_first):
    executor = ManualExecutor()
    monkeypatch.setattr(outbound, 'ThreadPoolExecutor', lambda **kw: executor)
    resolver = outbound.BoundedResolver(max_workers=1)
    async def run():
        for _ in range(20):
            task = asyncio.create_task(resolver.resolve('api.openai.com', 443))
            await asyncio.sleep(0)
            future = executor.futures[-1]
            if completion_first:
                future.set_result(PUBLIC)
                task.cancel()
            else:
                task.cancel()
                future.set_exception(socket.gaierror('late fixture failure'))
            await asyncio.gather(task, return_exceptions=True)
            assert resolver._unfinished == 0
        executor.immediate = True
        assert await resolver.resolve('api.openai.com', 443) == PUBLIC
    try: asyncio.run(run())
    finally: resolver.close(wait=True)


def test_close_races_with_submission_without_pool_replacement(native):
    gate, resolver = native
    ready = threading.Event()
    release_close = threading.Event()
    failures = []
    def closer():
        ready.set()
        if not release_close.wait(3):
            failures.append('close fixture watchdog')
        resolver.close(wait=False)
    thread = threading.Thread(target=closer)
    thread.start()
    async def run():
        await until(ready.is_set)
        task = asyncio.create_task(resolver.resolve('api.openai.com', 443))
        release_close.set()
        result = await asyncio.gather(task, return_exceptions=True) if task.done() else None
        await until(lambda: resolver._closed)
        gate.release.set()
        if result is None: result = await asyncio.gather(task, return_exceptions=True)
        assert result[0] == PUBLIC or isinstance(result[0], (httpcore.ConnectError, asyncio.CancelledError))
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
    try: asyncio.run(run())
    finally:
        release_close.set()
        gate.release.set()
        thread.join(timeout=2)
        assert not thread.is_alive() and not failures

def test_inline_failed_future_releases_once_and_recovers(monkeypatch):
    class ImmediateFailure(ManualExecutor):
        def submit(self, *a, **kw):
            future = Future()
            self.futures.append(future)
            if self.fail: future.set_exception(socket.gaierror('immediate failure'))
            else: future.set_result(PUBLIC)
            return future
    executor = ImmediateFailure()
    monkeypatch.setattr(outbound, 'ThreadPoolExecutor', lambda **kw: executor)
    resolver = outbound.BoundedResolver(max_workers=1)
    async def run():
        executor.fail = True
        for _ in range(20):
            with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
            assert resolver._unfinished == 0
        executor.fail = False
        assert await resolver.resolve('api.openai.com', 443) == PUBLIC
    try: asyncio.run(run())
    finally: resolver.close(wait=True)

@pytest.mark.parametrize('address', ['8.8.8.8', '2606:4700:4700::1111'])
def test_public_ipv4_ipv6_pinned_once_without_rebinding(monkeypatch, address):
    records = [(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))]
    resolver = type('Resolver', (), {'resolve': AsyncMock(side_effect=[records, AssertionError('second lookup')])})()
    tcp = AsyncMock(return_value='synthetic-stream')
    monkeypatch.setattr(outbound.AnyIOBackend, 'connect_tcp', tcp)
    async def run():
        assert await outbound.PublicModelBackend(resolver).connect_tcp('api.openai.com', 443, 1) == 'synthetic-stream'
        assert tcp.call_args.args[:2] == (address, 443)
        assert resolver.resolve.await_count == 1
    asyncio.run(run())

@pytest.mark.parametrize('records', [[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('invalid-address', 443))], [('malformed',)]])
def test_malformed_dns_never_reaches_tcp(monkeypatch, records):
    resolver = type('Resolver', (), {'resolve': AsyncMock(return_value=records)})()
    tcp = AsyncMock(side_effect=AssertionError('malformed answer reached TCP'))
    monkeypatch.setattr(outbound.AnyIOBackend, 'connect_tcp', tcp)
    async def run():
        with pytest.raises((ValueError, IndexError, httpcore.ConnectError)):
            await outbound.PublicModelBackend(resolver).connect_tcp('api.openai.com', 443, 1)
        assert tcp.await_count == 0
    asyncio.run(run())

@pytest.mark.parametrize('capacity', [0, 5, -1, True, 1.5])
def test_invalid_capacity_cannot_expand_process_limit(capacity):
    with pytest.raises(ValueError): outbound.BoundedResolver(max_workers=capacity)

def test_real_executor_enqueue_then_thread_start_failure_is_terminal(native, monkeypatch):
    gate, _ = native
    resolver = outbound.BoundedResolver()
    original_start = threading.Thread.start
    async def run():
        first = asyncio.create_task(resolver.resolve('api.openai.com', 443))
        await until(lambda: gate.started == 1)
        def fail_start(thread):
            if thread.name.startswith('model-dns'):
                raise RuntimeError('synthetic worker creation failure')
            return original_start(thread)
        monkeypatch.setattr(threading.Thread, 'start', fail_start)
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        monkeypatch.setattr(threading.Thread, 'start', original_start)
        assert resolver._closed and resolver._unfinished == 2
        for _ in range(20):
            with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        assert gate.started == gate.active == 1
        gate.release.set()
        assert await first == PUBLIC
        assert resolver._unfinished == 1
        resolver.close(wait=True)
        assert gate.started == gate.completed == 1
    try: asyncio.run(run())
    finally:
        monkeypatch.setattr(threading.Thread, 'start', original_start)
        gate.release.set()
        resolver.close(wait=True)


def test_close_before_submission_creates_no_executor(monkeypatch):
    def forbidden(**kwargs): raise AssertionError('closed resolver created executor')
    monkeypatch.setattr(outbound, 'ThreadPoolExecutor', forbidden)
    resolver = outbound.BoundedResolver()
    resolver.close()
    async def run():
        with pytest.raises(httpcore.ConnectError): await resolver.resolve('api.openai.com', 443)
        assert resolver._executor is None and resolver._unfinished == 0
    asyncio.run(run())

@pytest.mark.parametrize('include_capture', [False, True])
def test_asgi_default_limits_retain_native_dns_and_recover_same_adapter(native, monkeypatch, tmp_path, include_capture):
    """Application/backend seam only: synthetic proposal, never a LIVE provider.

    Evaluation variant changes only token/adapter. Mixed-route variant needs
    synthetic LIVE configuration to enter capture, retaining default 4/25 limits.
    """
    import httpx
    from agent.app import create_app
    from agent.dto import KycProposal
    from agent.llm_adapter import ModelUnavailable
    from agent.settings import Settings
    from agent.tests.test_agent import TOKEN, HEADERS, request_body
    gate, resolver = native
    tcp = AsyncMock(return_value='synthetic-stream')
    monkeypatch.setattr(outbound.AnyIOBackend, 'connect_tcp', tcp)
    class SyntheticDNSAdapter:
        model_name = 'synthetic-dns-route-fixture'
        def __init__(self):
            self.backends = []
            self.active = self.maximum = self.captures = 0
        async def propose(self, body):
            backend = outbound.PublicModelBackend()
            self.backends.append(backend)
            self.active += 1
            self.maximum = max(self.maximum, self.active)
            try:
                try:
                    stream = await backend.connect_tcp('api.openai.com', 443, 2.0)
                except httpcore.ConnectError as exc:
                    raise ModelUnavailable('synthetic DNS dependency unavailable') from exc
                assert stream == 'synthetic-stream'
                return KycProposal(status='NOT_VERIFIED', evidenceIds=[], explanation='Synthetic DNS seam recovery')
            finally:
                self.active -= 1
        async def capture(self, body):
            self.captures += 1
            return await self.propose(body), self.model_name
    settings = Settings(service_token=TOKEN)
    if include_capture:
        prompt = tmp_path / 'synthetic-prompt.txt'
        prompt.write_text('Synthetic fixture prompt, no provider request.')
        settings = Settings(service_token=TOKEN, mode='live', model='synthetic-fixture',
                            api_key='synthetic-never-transmitted', prompt_path=str(prompt))
    assert settings.max_parallel == 4 and settings.model_timeout_seconds == 25
    adapter = SyntheticDNSAdapter()
    app = create_app(settings, adapter)
    async def run():
        tasks = []
        routes = ['evaluations', 'captures'] if include_capture else ['evaluations']
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://synthetic.invalid') as client:
            async def request(index):
                return await client.post('/internal/v1/kyc/' + routes[index % len(routes)], headers=HEADERS, json=request_body())
            try:
                tasks = [asyncio.create_task(request(index)) for index in range(4)]
                await until(lambda: gate.started == 4)
                responses = await asyncio.wait_for(asyncio.gather(*tasks), 3)
                assert all(response.status_code == 503 and response.json() == {'decision': 'ERROR', 'reasonCode': 'DEPENDENCY_UNAVAILABLE'} for response in responses)
                assert adapter.active == 0 and adapter.maximum == 4
                assert gate.active == resolver._unfinished == 4
                assert tcp.await_count == 0
                for index in range(8):
                    response = await asyncio.wait_for(request(index), 1)
                    assert response.status_code == 503
                    assert response.json()['reasonCode'] == 'DEPENDENCY_UNAVAILABLE'
                assert gate.started == gate.peak == resolver._unfinished == 4
                assert resolver._executor._work_queue.qsize() == 0
                gate.release.set()
                await until(lambda: resolver._unfinished == 0)
                for index in range(len(routes)):
                    response = await asyncio.wait_for(request(index), 2)
                    assert response.status_code == 200
                    data = response.json()
                    if routes[index] == 'captures': data = data['response']
                    assert data['proposal']['status'] == 'NOT_VERIFIED'
                    assert data['modelMetadata']['model'] == adapter.model_name
                assert gate.started == gate.completed == 4 + len(routes)
                assert tcp.await_count == len(routes)
                assert len({id(backend) for backend in adapter.backends}) == len(adapter.backends)
                assert all(backend._resolver is resolver for backend in adapter.backends)
                assert adapter.active == 0
                assert bool(adapter.captures) == include_capture
            finally:
                gate.release.set()
                for task in tasks:
                    if not task.done(): task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run(run())
