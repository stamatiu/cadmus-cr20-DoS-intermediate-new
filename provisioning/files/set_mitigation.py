#!/usr/bin/env python3
import argparse, json, os, subprocess
import lab_api
from pathlib import Path
def config(profile,rate,burst):
    dry='on' if profile=='baseline' else 'off'
    engine='DetectionOnly' if profile=='baseline' else 'On'
    timeout='20s' if profile=='baseline' else '10s'
    rule=('limit_req zone=cr_perip nodelay;' if burst==0 else 'limit_req zone=cr_perip burst='+str(burst)+' nodelay;')
    return r'''
log_format cr_json escape=json '{"@timestamp":"$time_iso8601","event_source":"nginx","remote_addr":"$remote_addr","method":"$request_method","uri":"$uri","status":$status,"body_bytes_sent":$body_bytes_sent,"request_time":$request_time,"client_profile":"$http_x_cr_dos_client","phase":"$http_x_cr_dos_phase","run_id":"$http_x_cr_dos_run","user_agent":"$http_user_agent","limit_req_status":"$limit_req_status"}';
limit_req_zone $binary_remote_addr zone=cr_perip:10m rate=RATEr/s;
server {
    listen 10.10.0.30:80 default_server;
    server_name _;
    access_log /var/log/nginx/cr_dos_access.json cr_json;
    error_log /var/log/nginx/cr_dos_error.log warn;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/cr-dos/modsecurity.conf;
    modsecurity_rules 'SecRuleEngine ENGINE';
    client_header_timeout TIMEOUT;
    client_body_timeout TIMEOUT;
    keepalive_timeout 15s;
    send_timeout 15s;
    limit_req_status 429;
    limit_req_dry_run DRY;
    location / {
        RULE
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_read_timeout 5s;
        proxy_connect_timeout 2s;
    }
}
'''.replace('RATE',str(rate)).replace('ENGINE',engine).replace('TIMEOUT',timeout).replace('DRY',dry).replace('RULE',rule)
def apply(profile,rate,burst,runid=None):
    if os.geteuid()!=0: raise SystemExit('Run with sudo on web-waf')
    path=Path('/etc/nginx/sites-available/cr-dos.conf'); previous=path.read_text() if path.exists() else None
    path.write_text(config(profile,rate,burst))
    try:
        subprocess.run(['nginx','-t'],check=True)
        subprocess.run(['systemctl','reload','nginx'],check=True)
    except BaseException:
        if previous is not None: path.write_text(previous); subprocess.run(['systemctl','reload','nginx'])
        else: path.unlink(missing_ok=True)
        raise
    Path('/opt/cr-dos/mitigation-profile.json').write_text(json.dumps({'profile':profile,'rate':rate,'burst':burst}))
    result={'profile':{'profile':profile,'rate':rate,'burst':burst},'applied_utc':lab_api.utc(),'rejected_status':429,'nginx_test_and_reload':'passed'}
    if runid:lab_api.publish(runid,'control',result)
    print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('profile',choices=['baseline','protected']); p.add_argument('--rate',type=int,default=5); p.add_argument('--burst',type=int,default=10); p.add_argument('--run-id'); a=p.parse_args()
    if not 1<=a.rate<=20 or not 0<=a.burst<=30: p.error('rate must be 1..20 and burst 0..30')
    if a.run_id:lab_api.validate_id(a.run_id)
    apply(a.profile,a.rate,a.burst,a.run_id)
