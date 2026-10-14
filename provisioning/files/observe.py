#!/usr/bin/env python3
"""An independent sensor client checks the affected search function throughout."""
import argparse,concurrent.futures,datetime,json,socket,time
from collections import Counter
import lab_api,traffic
def run(s,persist=True):
    lab_api.wait_start(s);actual_start=lab_api.utc();start=datetime.datetime.fromisoformat(s['start_utc']).timestamp();end=datetime.datetime.fromisoformat(s['end_utc']).timestamp();futures=[];next_at=start;number=0;feedback_at=start+10
    def measured(profile,n):
        stamp=lab_api.utc();status,seconds=traffic.request(profile,s['run_id'],n)
        return {'utc':stamp,'profile':profile,'status':status,'seconds':round(seconds,6)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pending=set()
        while time.time()<end:
            wait=next_at-time.time()
            if wait>0:time.sleep(min(wait,max(0,end-time.time())))
            if time.time()>=end:break
            if time.time()>=feedback_at:
                recent=[f.result() for f in futures if f.done()][-80:]
                print('Recent independent client responses: '+json.dumps({'checked_utc':lab_api.utc(),'samples':len(recent),'first_sample_utc':recent[0]['utc'] if recent else None,'status_counts':dict(Counter(str(x['status']) for x in recent))}),flush=True);feedback_at=time.time()+10
            offset=time.time()-start;profile='peak' if s['scenario']=='capstone' and 600<=offset<780 else 'legitimate'
            next_at=max(next_at,time.time())+1/(8 if profile=='peak' else 2);pending={f for f in pending if not f.done()}
            if len(pending)>=4:continue
            f=pool.submit(measured,profile,number);futures.append(f);pending.add(f);number+=1
        samples=[f.result() for f in futures]
    groups={}
    for profile in {x['profile'] for x in samples}:
        part=[x for x in samples if x['profile']==profile]
        groups[profile]={'requests':len(part),'status_counts':dict(Counter(str(x['status']) for x in part)),'successful_latency':traffic.latency([x['seconds'] for x in part if x['status']==200])}
    report={'run_id':s['run_id'],'scenario':s['scenario'],'start_utc':actual_start,'scheduled_start_utc':s['start_utc'],'end_utc':lab_api.utc(),'scheduled_end_utc':s['end_utc'],'completed':True,'source':'10.10.0.20','target_path':'/api/search','by_client_profile':groups,'samples':samples}
    if persist:lab_api.publish(s['run_id'],'observer',report)
    print(json.dumps({k:v for k,v in report.items() if k!='samples'},indent=2));return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--run-id',required=True);p.add_argument('--seconds',type=int);a=p.parse_args()
    if socket.gethostname().split('.')[0]!='sensor':p.error('Run the independent client command on the sensor machine.')
    lab_api.validate_id(a.run_id)
    if a.seconds is None:s=lab_api.session(a.run_id)
    else:
        if not 5<=a.seconds<=180:p.error('A separate observation must last between 5 and 180 seconds.')
        start=datetime.datetime.now(datetime.timezone.utc);s={'scenario':'comparison','run_id':a.run_id,'start_utc':start.isoformat(),'end_utc':(start+datetime.timedelta(seconds=a.seconds)).isoformat()}
    run(s)
