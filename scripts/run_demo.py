"""Run two registered mock applications through real HTTP APIs. No paid model or real money."""
import json, os, re, time, uuid
from urllib.request import Request, urlopen
from urllib.error import HTTPError
BASE = os.environ.get('FUSE_BASE_URL', 'http://localhost:8080').rstrip('/')
POLL_SECONDS = 1.0  # At most 60 reads/minute; the server allows 120 per actor.
RUN_SECONDS = 90.0


class RateLimited(Exception):
    def __init__(self, retry_after):
        # The demo server uses delta-seconds. Unsupported/missing values fall
        # back to its 60-second window; never trust arbitrary header text.
        value = retry_after if isinstance(retry_after, str) else ''
        self.delay = max(POLL_SECONDS, int(value)) if re.fullmatch(r'[0-9]{1,6}', value) else 60.0


def pause(seconds, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SystemExit('Demo deadline reached; no completion claimed')
    time.sleep(min(seconds, remaining))
    if time.monotonic() >= deadline:
        raise SystemExit('Demo deadline reached; no completion claimed')


def call(method, path, token, deadline, body=None):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SystemExit('Demo deadline reached; no completion claimed')
        try:
            result = api(method, path, token, body, timeout=min(35, remaining))
            if time.monotonic() >= deadline:
                raise SystemExit('Demo deadline reached; no completion claimed')
            return result
        except RateLimited as limited:
            if method != 'GET':
                # Never synthesize a new mutation action as a retry strategy.
                raise SystemExit('HTTP 429 on mutation; no completion claimed') from None
            pause(limited.delay, deadline)

def api(method, path, token, body=None, key=None, timeout=35):
    headers={'Authorization': 'Bearer '+token, 'Content-Type':'application/json'}
    if body is not None: headers['Idempotency-Key']=key or str(uuid.uuid4())
    req=Request(BASE+'/api/v1'+path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as response: return json.load(response)
    except HTTPError as e:
        try:
            if e.code == 429:
                raise RateLimited(e.headers.get('Retry-After')) from None
            # Error bodies are untrusted and may contain sensitive diagnostics.
            raise SystemExit(f'HTTP {e.code}; no completion claimed') from None
        finally:
            e.close()

def run(customer):
    token=os.environ[f'FUSE_CUSTOMER_{customer}_TOKEN']
    deadline=time.monotonic()+RUN_SECONDS
    result=call('POST','/workflows',token,deadline,{'businessReference':f'APP-DEMO-{customer}-001','customerId':f'customer-{customer}','amountKrw':1000000,'payoutAccountId':f'00000000-0000-4000-8000-000000000{customer}'})
    wid=result['workflowId']; approved=False
    while time.monotonic()<deadline:
        current=call('GET',f'/workflows/{wid}',token,deadline)
        if current['state']=='WAIT_APPROVAL' and customer==102 and not approved:
            reviewer=os.environ['FUSE_REVIEWER_TOKEN']; preview=call('GET',f'/workflows/{wid}/approval-preview',reviewer,deadline)
            call('POST',f'/workflows/{wid}/approvals',reviewer,deadline,{'decision':'APPROVE','reviewSnapshotHash':preview['reviewSnapshotHash'],'comment':'Explicit demo reviewer confirms exact mock terms'})
            approved=True
        elif current['state'] in ('PAID','BLOCKED','REJECTED','ON_HOLD'):
            print(json.dumps({'customer':customer,'workflowId':wid,'state':current['state'],'usedRisk':current['usedRisk'],'reservedRisk':current['reservedRisk'],'reasonCodes':current['reasonCodes']},ensure_ascii=False))
            expected='PAID' if customer==102 else 'BLOCKED'
            if current['state']!=expected: raise SystemExit(f'Expected {expected}, observed {current["state"]}; inspect trace. A failure is not a successful security test.')
            return
        pause(POLL_SECONDS, deadline)
    raise SystemExit(f'Timeout waiting for workflow {wid}; no completion claimed')

if __name__=='__main__':
    run(101); run(102)
