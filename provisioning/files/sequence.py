#!/usr/bin/env python3
import argparse,datetime,json,time
import lab_api,load,traffic
PLANS={'incident':[('baseline',60),('python',180),('calm',120)],'drill':[('baseline',20),('round-tool',60),('calm',40)],'capstone':[('baseline',180),('python',180),('calm',120),('slow',180),('python',120),('calm',120)]}
def run(s,tool='python'):
    lab_api.wait_start(s);deadline=datetime.datetime.fromisoformat(s['start_utc']).timestamp();events=[];failed=False
    for phase,duration in PLANS[s['scenario']]:
        deadline+=duration;event={'phase':phase,'start_utc':lab_api.utc(),'scheduled_end_utc':datetime.datetime.fromtimestamp(deadline,datetime.timezone.utc).isoformat()};print('The current phase is '+phase+' at '+event['start_utc'],flush=True)
        budget=max(0,int(deadline-time.time())-7)
        try:
            if phase=='calm':event['completed']=True
            elif budget<5:event.update(completed=False,error='There is insufficient time remaining in this slot.')
            elif phase=='baseline':traffic.run('baseline',min(180,budget),s['run_id'],True);event['completed']=True
            else:
                result=load.execute(tool if phase=='round-tool' else phase,min(180,budget),s['run_id']);event['load']=result;event['completed']=result['completed']
        except Exception as error:event.update(completed=False,error=str(error))
        event['generator_finished_utc']=lab_api.utc();failed|=not event['completed']
        while time.time()<deadline:time.sleep(min(.25,deadline-time.time()))
        event['end_utc']=lab_api.utc();events.append(event)
        if failed:break
    report={'scenario':s['scenario'],'run_id':s['run_id'],'scheduled_start_utc':s['start_utc'],'scheduled_end_utc':s['end_utc'],'finished_utc':lab_api.utc(),'duration_budget_seconds':sum(d for _,d in PLANS[s['scenario']]),'completed':not failed and len(events)==len(PLANS[s['scenario']]),'events':events}
    lab_api.publish(s['run_id'],'sequence',report);print(json.dumps(report,indent=2));return report
def main(scenario):
    p=argparse.ArgumentParser();p.add_argument('--run-id',required=True)
    if scenario=='drill':p.add_argument('--tool',choices=['python','wrk','slow'],required=True)
    a=p.parse_args();s=lab_api.session(a.run_id)
    if s['scenario']!=scenario:p.error('First create a session for the '+scenario+' scenario.')
    r=run(s,getattr(a,'tool','python'));raise SystemExit(0 if r['completed'] else 1)
