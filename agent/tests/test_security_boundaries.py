"""SC-02/04/08/09/15/17: isolated fakes; no external or metadata requests."""
import asyncio
import hashlib
import json
import socket
from unittest.mock import AsyncMock, Mock

import httpcore
import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agent.app import create_app
from agent.dto import KycRequest, strict_json_loads
from agent.llm_adapter import LiveAdapter, ModelOutputInvalid
from agent.outbound import PublicModelBackend, BoundedResolver
from agent.prompt import PromptConfigurationError, load_system_prompt
from agent.settings import Settings
from agent.tests.test_agent import HEADERS, TOKEN, PATH, request_body, rehash


class CountingAdapter:
    model_name = "test-only"
    def __init__(self): self.calls = 0
    async def propose(self, body):
        self.calls += 1
        raise AssertionError("invalid inputs must never reach model")


@pytest.mark.parametrize("route", ["evaluations", "captures"])
@pytest.mark.parametrize("tokens", [[], ["wrong"], [TOKEN, TOKEN], [TOKEN, "wrong"], [TOKEN + "," + TOKEN], [" " + TOKEN]])
def test_authentication_precedes_json_and_configuration(route, tokens):
    adapter = CountingAdapter()
    app = create_app(Settings(service_token=TOKEN, mode="live"), adapter)
    headers = [("X-Fuse-Service-Token", token) for token in tokens]
    headers += [("Content-Type", "application/json")]
    result = TestClient(app).post(f"/internal/v1/kyc/{route}", headers=headers, content='{' * 300000)
    assert result.status_code == 401
    assert adapter.calls == 0


@pytest.mark.parametrize("token", ["", "CHANGE_ME", "x" * 31, "x" * 32 + ",", "x" * 32 + " "])
def test_invalid_token_prevents_runtime_startup(token):
    with pytest.raises(RuntimeError, match="service token"):
        with TestClient(create_app(Settings(service_token=token))): pass


def test_strict_depth_before_recursive_decoder_and_escaped_delimiters():
    assert strict_json_loads('[' * 16 + '0' + ']' * 16)
    for payload in ['[' * 17 + '0' + ']' * 17, '[' * 5000 + '0' + ']' * 5000,
                    '{"x":1}{}', '{"x":Infinity}', '{"x":1,"x":2}', b'"\xff"']:
        with pytest.raises((ValueError, UnicodeError)): strict_json_loads(payload)
    assert strict_json_loads(json.dumps({'text': '[{}]\\"' * 100}))


@pytest.mark.parametrize("text,valid", [("a" * 16384, True), ("a" * 16385, False), ("한" * 5461, True), ("한" * 5462, False), ("😀" * 4096, True), ("😀" * 4097, False)])
def test_document_limit_is_utf8_bytes(text, valid):
    body = request_body(text=text)
    if valid: assert KycRequest.model_validate(body)
    else:
        with pytest.raises(ValidationError): KycRequest.model_validate(body)


@pytest.mark.parametrize("change", [lambda b: b.update(documents=b['documents'] * 9),
    lambda b: b.update(evidenceFacts=b['evidenceFacts'] * 6), lambda b: b.update(generation=2147483648),
    lambda b: b.update(generation=1.0), lambda b: b['documents'][0].update(documentVersion=True),
    lambda b: b.update(callbackUrl="http://metadata.invalid")])
def test_invalid_dto_never_calls_model(change):
    adapter=CountingAdapter();body=request_body();change(body)
    result=TestClient(create_app(Settings(service_token=TOKEN),adapter)).post(PATH,headers=HEADERS,json=rehash(body))
    assert result.status_code == 422 and adapter.calls == 0


def test_compressed_requests_rejected_before_decode():
    adapter=CountingAdapter()
    result=TestClient(create_app(Settings(service_token=TOKEN),adapter)).post(PATH,
        headers={**HEADERS,"Content-Type":"application/json","Content-Encoding":"gzip"},content=b"opaque")
    assert result.status_code == 415 and adapter.calls == 0


def test_private_file_limits_symlinks_parent_links_and_traversal(tmp_path):
    good=tmp_path/'private.txt';good.write_text('a'*65536)
    assert len(load_system_prompt(str(good))) == 65536
    good.write_text('a'*65537)
    with pytest.raises(PromptConfigurationError): load_system_prompt(str(good))
    good.write_text('fixture-only')
    link=tmp_path/'linked.txt';link.symlink_to(good)
    parent=tmp_path/'linked-parent';parent.symlink_to(tmp_path,target_is_directory=True)
    for path in [link, parent/'private.txt', tmp_path/'..'/tmp_path.name/'private.txt']:
        with pytest.raises(PromptConfigurationError): load_system_prompt(str(path))


@pytest.mark.parametrize("address", ["127.0.0.1","169.254.169.254","10.0.0.1","::1","fc00::1","::ffff:127.0.0.1"])
def test_model_dns_rejects_private_at_connection_without_socket(monkeypatch,address):
    async def run():
        monkeypatch.setattr(socket,"getaddrinfo",Mock(return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,"",(address,443))]))
        monkeypatch.setattr('agent.outbound.AnyIOBackend.connect_tcp',AsyncMock(side_effect=AssertionError("socket must not open")))
        owner = BoundedResolver()
        try:
            with pytest.raises(httpcore.ConnectError): await PublicModelBackend(owner).connect_tcp("api.openai.com",443,2)
        finally:
            owner.close(wait=True)
    asyncio.run(run())


def test_dns_pin_is_passed_to_socket_and_no_reinterpretation(monkeypatch):
    async def run():
        resolver=Mock(side_effect=[[(socket.AF_INET,socket.SOCK_STREAM,6,"",("8.8.8.8",443))],AssertionError("second DNS lookup")])
        monkeypatch.setattr(socket,"getaddrinfo",resolver)
        connect=AsyncMock(return_value='fake-stream')
        monkeypatch.setattr('agent.outbound.AnyIOBackend.connect_tcp',connect)
        owner = BoundedResolver()
        try:
            assert await PublicModelBackend(owner).connect_tcp("api.openai.com",443,2) == 'fake-stream'
        finally:
            owner.close(wait=True)
        assert connect.call_args.args[0] == '8.8.8.8'
        assert resolver.call_count == 1
    asyncio.run(run())


def test_concurrency_queue_is_bounded_and_recovers():
    async def run():
        class Barrier:
            model_name='barrier'
            active=0;maximum=0
            def __init__(self): self.started=asyncio.Event();self.release=asyncio.Event()
            async def propose(self,body):
                self.active+=1;self.maximum=max(self.maximum,self.active)
                if self.active==4:self.started.set()
                try:
                    await self.release.wait()
                    from agent.dto import KycProposal
                    return KycProposal(status='NEEDS_REVIEW',evidenceIds=[],explanation='fixture')
                finally:self.active-=1
        adapter=Barrier()
        app=create_app(Settings(service_token=TOKEN,model_timeout_seconds=2),adapter)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
            active=[asyncio.create_task(client.post(PATH,headers=HEADERS,json=request_body())) for _ in range(4)]
            await adapter.started.wait()
            waiting=[asyncio.create_task(client.post(PATH,headers=HEADERS,json=request_body())) for _ in range(4)]
            await asyncio.sleep(0)
            overflow=await client.post(PATH,headers=HEADERS,json=request_body())
            assert overflow.status_code==503 and adapter.maximum==4
            adapter.release.set()
            assert all(r.status_code==200 for r in await asyncio.gather(*active,*waiting))
            assert (await client.post(PATH,headers=HEADERS,json=request_body())).status_code==200
            assert adapter.active==0 and adapter.maximum==4
    asyncio.run(run())


@pytest.mark.parametrize('kind', ['oversized', 'deep', 'utf8', 'duplicate', 'compressed', 'authority'])
def test_malformed_provider_responses_are_model_errors(tmp_path,monkeypatch,kind):
    path=tmp_path/'private.txt';path.write_text('fixture-only-system')
    settings=Settings(service_token=TOKEN,mode='live',model='fake',api_key='fake',prompt_path=str(path))
    bodies={'oversized':b' '*65537,'deep':('['*17+'0'+']'*17).encode(),'utf8':b'\xff',
            'duplicate':b'{"choices":[],"choices":[]}', 'compressed':b'opaque',
            'authority':json.dumps({'choices':[{'finish_reason':'stop','message':{'content':json.dumps({
                'status':'VERIFIED','evidenceIds':[],'explanation':'fixture','role':'ADMIN'})}}]}).encode()}
    seen=[]
    def respond(request):
        seen.append(request)
        return httpx.Response(200,content=bodies[kind],headers={'Content-Encoding':'gzip'} if kind=='compressed' else {})
    monkeypatch.setattr('agent.llm_adapter.model_transport',lambda:httpx.MockTransport(respond))
    with pytest.raises(ModelOutputInvalid):
        asyncio.run(LiveAdapter(settings).propose(KycRequest.model_validate(request_body(text='http://metadata.invalid'))))
    assert len(seen)==1
    assert str(seen[0].url)=='https://api.openai.com/v1/chat/completions'


@pytest.mark.parametrize('status',[301,302,307,308])
def test_provider_redirects_never_forward_credentials(tmp_path,monkeypatch,status):
    from agent.llm_adapter import ModelUnavailable
    path=tmp_path/'private.txt';path.write_text('fixture-only-system')
    settings=Settings(service_token=TOKEN,mode='live',model='fake',api_key='fake',prompt_path=str(path))
    seen=[]
    def respond(request):
        seen.append(request)
        return httpx.Response(status,headers={'Location':'http://forbidden.invalid/not-called'})
    monkeypatch.setattr('agent.llm_adapter.model_transport',lambda:httpx.MockTransport(respond))
    with pytest.raises(ModelUnavailable):asyncio.run(LiveAdapter(settings).propose(KycRequest.model_validate(request_body())))
    assert len(seen)==1 and seen[0].url.host=='api.openai.com'


def test_request_header_limit_and_api_docs_are_closed():
    adapter=CountingAdapter();client=TestClient(create_app(Settings(service_token=TOKEN),adapter))
    assert client.post(PATH,headers={**HEADERS,'X-Extra':'x'*16384},json=request_body()).status_code==431
    for path in ['/docs','/redoc','/openapi.json']: assert client.get(path).status_code==404
    assert adapter.calls==0


def test_cancelled_model_call_releases_semaphore_and_admission_capacity():
    async def run():
        from agent.dto import KycProposal
        class CancelOnce:
            model_name='fixture'
            calls=0
            def __init__(self): self.started=asyncio.Event();self.finished=asyncio.Event()
            async def propose(self,body):
                self.calls+=1
                if self.calls==1:
                    self.started.set()
                    try: await asyncio.Event().wait()
                    finally: self.finished.set()
                return KycProposal(status='NEEDS_REVIEW',evidenceIds=[],explanation='fixture')
        adapter=CancelOnce();app=create_app(Settings(service_token=TOKEN,max_parallel=1),adapter)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
            task=asyncio.create_task(client.post(PATH,headers=HEADERS,json=request_body()))
            await adapter.started.wait();task.cancel()
            with pytest.raises(asyncio.CancelledError):await task
            await asyncio.wait_for(adapter.finished.wait(),1)
            assert (await client.post(PATH,headers=HEADERS,json=request_body())).status_code==200
    asyncio.run(run())
