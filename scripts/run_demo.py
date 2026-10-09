"""Run two registered mock applications through real HTTP APIs. No paid model or real money."""
import json, os, time, uuid
from urllib.request import Request, urlopen
from urllib.error import HTTPError
BASE = os.environ.get('FUSE_BASE_URL', 'http://localhost:8080').rstrip('/')

def api(method, path, token, body=None, key=None):
    headers={'Authorization': 'Bearer '+token, 'Content-Type':'application/json'}
    if body is not None: headers['Idempotency-Key']=key or str(uuid.uuid4())
    req=Request(BASE+'/api/v1'+path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
    try:
        with urlopen(req, timeout=35) as response: return json.load(response)
    except HTTPError as e:
        raise SystemExit(f'HTTP {e.code}: {e.read().decode()}')

def run(customer):
    token=os.environ[f'FUSE_CUSTOMER_{customer}_TOKEN']
    result=api('POST','/workflows',token,{'businessReference':f'APP-DEMO-{customer}-001','customerId':f'customer-{customer}','amountKrw':1000000,'payoutAccountId':f'00000000-0000-4000-8000-000000000{customer}'})
    wid=result['workflowId']; approved=False; deadline=time.monotonic()+90
    while time.monotonic()<deadline:
        current=api('GET',f'/workflows/{wid}',token)
        if current['state']=='WAIT_APPROVAL' and customer==102 and not approved:
            reviewer=os.environ['FUSE_REVIEWER_TOKEN']; preview=api('GET',f'/workflows/{wid}/approval-preview',reviewer)
            api('POST',f'/workflows/{wid}/approvals',reviewer,{'decision':'APPROVE','reviewSnapshotHash':preview['reviewSnapshotHash'],'comment':'Explicit demo reviewer confirms exact mock terms'})
            approved=True
        elif current['state'] in ('PAID','BLOCKED','REJECTED','ON_HOLD'):
            print(json.dumps({'customer':customer,'workflowId':wid,'state':current['state'],'usedRisk':current['usedRisk'],'reservedRisk':current['reservedRisk'],'reasonCodes':current['reasonCodes']},ensure_ascii=False))
            expected='PAID' if customer==102 else 'BLOCKED'
            if current['state']!=expected: raise SystemExit(f'Expected {expected}, observed {current["state"]}; inspect trace. A failure is not a successful security test.')
            return
        time.sleep(.3)
    raise SystemExit(f'Timeout waiting for workflow {wid}; no completion claimed')

if __name__=='__main__':
    run(101); run(102)
