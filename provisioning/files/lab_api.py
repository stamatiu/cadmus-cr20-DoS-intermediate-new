#!/usr/bin/env python3
"""Coordination and original evidence transfer inside the assigned sandbox."""
import datetime,json,re,socket,time,urllib.request,urllib.parse
from pathlib import Path
API='http://10.10.0.30:8081'
NODES={'attacker','sensor','siem','web-waf'}
def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def validate_id(value):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',value): raise ValueError('Choose a run identifier containing 1 to 40 letters, digits, hyphens or underscores.')
    return value
def call(path,data=None,raw=None,timeout=20):
    body=raw if raw is not None else json.dumps(data).encode() if data is not None else None
    request=urllib.request.Request(API+path,data=body,headers={'Content-Type':'application/octet-stream' if raw is not None else 'application/json'})
    with urllib.request.urlopen(request,timeout=timeout) as response:
        body=response.read()
        return body if response.headers.get_content_type()=='application/zip' else json.loads(body)
def session(runid): return call('/session?'+urllib.parse.urlencode({'run_id':validate_id(runid)}))
def wait_start(session):
    start=datetime.datetime.fromisoformat(session['start_utc']).timestamp()
    if time.time()>start+10: raise ValueError('The shared start time has passed. Restore the baseline and create another session with a new run identifier.')
    while time.time()<start: time.sleep(min(.25,start-time.time()))
def publish(runid,kind,data):
    validate_id(runid);node=socket.gethostname().split('.')[0]
    if node not in NODES: raise ValueError('Run this command inside one of the assigned exercise machines.')
    record={'run_id':runid,'node':node,'kind':kind,'recorded_utc':utc(),'data':data}
    folder=Path.home()/'cr-dos-results'/runid;folder.mkdir(parents=True,exist_ok=True)
    (folder/(kind+'-'+str(time.time_ns())+'.json')).write_text(json.dumps(record,indent=2))
    call('/record',record);return record
