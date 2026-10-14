#!/usr/bin/env python3
"""Bounded workloads for the one assigned application address."""
import argparse,concurrent.futures,json,math,time,urllib.request,urllib.error,uuid
from collections import Counter
import lab_api
TARGET='http://10.10.0.30'
PROFILES={'baseline':(2,2),'legitimate':(2,2),'peak':(8,4),'attack':(100,16)}
BASELINE=['/','/status','/api/search?q=baseline','/about','/missing']
def request(profile,runid,n):
    path=BASELINE[n%5] if profile=='baseline' else '/api/search?q=lab' if profile=='attack' else '/api/search?q=legitimate'
    headers={'X-CR-DOS-Run':runid,'X-CR-DOS-Phase':'legitimate' if profile=='peak' else profile,'X-CR-DOS-Client':'peak' if profile=='peak' else 'normal','User-Agent':'cr-dos/'+profile}
    started=time.monotonic()
    try:
        with urllib.request.urlopen(urllib.request.Request(TARGET+path,headers=headers),timeout=3) as r:r.read();status=r.status
    except urllib.error.HTTPError as e:e.read();status=e.code
    except (urllib.error.URLError,TimeoutError,OSError):status=0
    return status,time.monotonic()-started
def latency(values):
    values=sorted(values)
    return {'count':len(values),'mean_seconds':round(sum(values)/len(values),6) if values else None,'p95_seconds':round(values[max(0,math.ceil(.95*len(values))-1)],6) if values else None}
def run(profile,seconds,runid,persist=False):
    lab_api.validate_id(runid);rate,workers=PROFILES[profile];started=time.monotonic();stamp=lab_api.utc();futures=[];scheduled=0
    def measured(n):
        utc=lab_api.utc();status,seconds=request(profile,runid,n)
        return {'utc':utc,'profile':profile,'status':status,'seconds':round(seconds,6)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        pending=set()
        for n in range(rate*seconds):
            wait=started+n/rate-time.monotonic()
            if wait>0:time.sleep(wait)
            if time.monotonic()-started>=seconds:break
            scheduled+=1;pending={f for f in pending if not f.done()}
            if len(pending)>=workers:continue
            f=pool.submit(measured,n);futures.append(f);pending.add(f)
        samples=[f.result() for f in futures]
    elapsed=time.monotonic()-started
    report={'run_id':runid,'profile':profile,'target':TARGET,'start_utc':stamp,'end_utc':lab_api.utc(),'duration_budget_seconds':seconds,'elapsed_seconds':round(elapsed,3),'offered_rate_rps':rate,'worker_limit':workers,'scheduled_requests':scheduled,'skipped_due_to_worker_budget':scheduled-len(samples),'requests':len(samples),'achieved_rate_rps':round(len(samples)/elapsed,3),'status_counts':dict(Counter(str(x['status']) for x in samples)),'all_response_latency':latency([x['seconds'] for x in samples]),'successful_latency':latency([x['seconds'] for x in samples if x['status']==200]),'samples':samples,'explanation':'Status 0 indicates a client transport failure. Successful latency includes only HTTP 200 responses.'}
    if persist:lab_api.publish(runid,'traffic',report)
    print(json.dumps({k:v for k,v in report.items() if k!='samples'},indent=2),flush=True);return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('profile',choices=PROFILES);p.add_argument('--seconds',type=int,default=60);p.add_argument('--run-id',default=uuid.uuid4().hex[:10]);a=p.parse_args()
    if not 1<=a.seconds<=180:p.error('The traffic duration must be between 1 and 180 seconds.')
    run(a.profile,a.seconds,a.run_id,True)
