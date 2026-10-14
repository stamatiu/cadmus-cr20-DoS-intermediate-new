#!/usr/bin/env python3
import json, time, subprocess, urllib.request
from pathlib import Path
ES='http://10.10.0.10:9200'; KB='http://10.10.0.10:5601'
def send(url,payload=None,method=None):
    req=urllib.request.Request(url,data=json.dumps(payload).encode() if payload is not None else None,headers={'Content-Type':'application/json','kbn-xsrf':'cr-dos'},method=method)
    with urllib.request.urlopen(req,timeout=15) as r: return json.load(r)
for attempt in range(60):
    try:
        send(ES)
        if send(KB+'/api/status')['status']['overall']['level']=='available': break
    except Exception: pass
    time.sleep(10)
else: raise SystemExit('SIEM services did not become healthy. Check Docker logs and flavor RAM.')
PROPERTIES={'@timestamp': {'type': 'date'}, 'remote_addr': {'type': 'ip'}, 'uri': {'type': 'keyword'}, 'method': {'type': 'keyword'}, 'phase': {'type': 'keyword'}, 'client_profile': {'type': 'keyword'}, 'run_id': {'type': 'keyword'}, 'status': {'type': 'integer'}, 'request_time': {'type': 'double'}, 'body_bytes_sent': {'type': 'long'}, 'limit_req_status': {'type': 'keyword'}, 'user_agent': {'type': 'keyword'}}
send(ES+'/_index_template/cr-dos-waf',{'index_patterns':['cr-dos-waf-*'],'template':{'mappings':{'properties':PROPERTIES}}},'PUT')
result=subprocess.run(['curl','-fsS','-X','POST',KB+'/api/saved_objects/_import?overwrite=true','-H','kbn-xsrf: cr-dos','--form','file=@'+str(Path(__file__).with_name('dashboards.ndjson'))],check=True,capture_output=True,text=True)
report=json.loads(result.stdout)
if not report.get('success'): raise SystemExit('Kibana object import failed: '+json.dumps(report))
print('Healthy SIEM. Imported '+str(report.get('successCount'))+' data views, visualizations and dashboards.')
