"""Explicit real, isolated-lab response verification; never run by unittest discovery."""
import argparse
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--execute',action='store_true',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--phase',choices=['normal','prepare-restart','verify-restart'],default='normal')
    args=parser.parse_args();folder=Path(args.output);folder.mkdir(parents=True,exist_ok=True)
    record=folder/(args.phase+'.json')
    if record.exists():raise SystemExit('Existing evidence will not be overwritten.')
    base='http://127.0.0.1:8768'
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token=json.load(opener.open(base+'/api/config'))['csrf']
    events=[]
    def call(path,data=None,expect=200):
        headers={'X-PacketPilot-Token':token,'Content-Type':'application/json'}
        req=urllib.request.Request(base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
        try:
            with opener.open(req,timeout=40) as r:status=r.status;result=json.load(r)
        except urllib.error.HTTPError as exc:status=exc.code;result=json.load(exc)
        clean={k:v for k,v in result.items() if k not in ('approval_token','csrf')} if isinstance(result,dict) else result
        events.append({'at':datetime.now(timezone.utc).isoformat(),'path':path,'status':status,'response':clean})
        record.write_text(json.dumps({'phase':args.phase,'events':events},indent=2))
        if status != expect:raise AssertionError((path,status,result))
        return result
    if args.phase=='verify-restart':
        prepared=json.loads((folder/'prepare-restart.json').read_text())
        saved=prepared['events'][-1]['response']; review_id=saved['review_id'];action_id=saved['action_id']
        actions=call(f'/api/reviews/{review_id}/actions')
        action=next(a for a in actions if a['id']==action_id)
        assert action['state']=='rolled_back',action
        assert action['events'][-1]['event']=='restart_recovery',action
    else:
        call('/api/lab/status')
        review=call('/api/lab/capture',{'provider':'rules'},201)
        rid=review['id'];root=f'/api/reviews/{rid}/actions'
        proposal=call(root+'/propose',{'target':'10.77.0.20','duration_seconds':120 if args.phase=='prepare-restart' else 20,'reason':'Authorised controlled-response verification; known benign lab traffic, not claimed malicious.'})
        body={'approval_token':proposal['approval_token'],'confirmation':proposal['confirmation']}
        if args.phase=='normal':
            call(root+'/'+proposal['id']+'/approve',body|{'confirmation':'yes'},400)
            call(root+'/propose',{'target':'192.168.37.128','duration_seconds':20,'reason':'negative scope test'},422)
        active=call(root+'/'+proposal['id']+'/approve',body)
        assert active['state']=='active',active
        if args.phase=='prepare-restart':
            events.append({'at':datetime.now(timezone.utc).isoformat(),'response':{'review_id':rid,'action_id':proposal['id']}})
        else:
            call(root+'/'+proposal['id']+'/approve',body,400)
            # Explicit rollback POST: the body is empty JSON, not an unsafe GET.
            rolled=call(root+'/'+proposal['id']+'/rollback',{})
            assert rolled['state']=='rolled_back',rolled
            expiry=call(root+'/propose',{'target':'10.77.0.20','duration_seconds':5,'reason':'Verify independent timed rollback.'})
            call(root+'/'+expiry['id']+'/approve',{'approval_token':expiry['approval_token'],'confirmation':expiry['confirmation']})
            time.sleep(6)
            actions=call(root)
            expired=next(a for a in actions if a['id']==expiry['id'])
            assert expired['state']=='expired',expired
            exported=call(f'/api/reviews/{rid}/export')
            assert len(exported['response_actions'])==2
            assert 'approval_hash' not in json.dumps(exported) and 'approval_token' not in json.dumps(exported)
    record.write_text(json.dumps({'phase':args.phase,'passed':True,'events':events},indent=2))
    print(json.dumps({'passed':True,'phase':args.phase,'record':str(record)}))


if __name__=='__main__':main()
