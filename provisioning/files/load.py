#!/usr/bin/env python3
"""Record each bounded tool execution, including failure and actual times."""
import argparse,json,subprocess,sys,time
from pathlib import Path
import lab_api
def execute(tool,seconds,runid,persist=True):
    lab_api.validate_id(runid)
    if not 5<=seconds<=180:raise ValueError('The tool duration must be between 5 and 180 seconds.')
    if tool=='python':cmd=[sys.executable,str(Path(__file__).with_name('traffic.py')),'attack','--seconds',str(seconds),'--run-id',runid]
    elif tool=='wrk':cmd=['wrk','-t2','-c16','-d'+str(seconds)+'s','--timeout','3s','-H','X-CR-DOS-Run: '+runid,'-H','X-CR-DOS-Phase: attack','-H','User-Agent: cr-dos/wrk','http://10.10.0.30/api/search?q=lab']
    elif tool=='slow':cmd=['slowhttptest','-H','-c','20','-r','2','-i','5','-l',str(seconds),'-u','http://10.10.0.30/api/search?q=lab','-p','3']
    else:raise ValueError('Choose the python, wrk or slow tool.')
    stamp=lab_api.utc();origin=time.monotonic()
    try:
        r=subprocess.run(cmd,timeout=seconds+6,capture_output=True,text=True)
        report={'tool':tool,'command':cmd,'start_utc':stamp,'end_utc':lab_api.utc(),'requested_seconds':seconds,'elapsed_seconds':round(time.monotonic()-origin,3),'returncode':r.returncode,'completed':r.returncode==0,'stdout':r.stdout[-22000:],'stderr':r.stderr[-5000:]}
    except (OSError,subprocess.TimeoutExpired) as e:
        report={'tool':tool,'command':cmd,'start_utc':stamp,'end_utc':lab_api.utc(),'requested_seconds':seconds,'returncode':None,'completed':False,'error':str(e)}
    if persist:lab_api.publish(runid,'load',report)
    print(json.dumps(report,indent=2),flush=True);return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--tool',choices=['python','wrk','slow'],required=True);p.add_argument('--seconds',type=int,default=60);p.add_argument('--run-id',required=True);a=p.parse_args();r=execute(a.tool,a.seconds,a.run_id);raise SystemExit(0 if r['completed'] else 1)
