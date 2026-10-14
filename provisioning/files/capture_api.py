#!/usr/bin/env python3
"""Private packet capture, shared schedules and bounded evidence file transfer."""
import datetime,json,re,subprocess,tempfile,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
ROOT=Path('/var/lib/cr-dos/coordinator')
PROFILE=Path('/opt/cr-dos/mitigation-profile.json')
CONFIG=Path('/etc/nginx/sites-available/cr-dos.conf')
NODES={'10.10.0.10':'siem','10.10.0.20':'sensor','10.10.0.30':'web-waf','10.10.0.40':'attacker','127.0.0.1':'web-waf'}
DURATIONS={'incident':360,'drill':120,'capstone':900}
LOCK=threading.Lock();STORE_LOCK=threading.Lock()
def valid_id(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',value):raise ValueError('The run identifier is invalid.')
    return value
def filename(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,120}',value) or value in ('.','..'):raise ValueError('The filename is invalid.')
    return value
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True);temp=path.with_suffix('.tmp');temp.write_text(json.dumps(data,indent=2));temp.replace(path)
class Handler(BaseHTTPRequestHandler):
    def reply(self,data):
        body=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def authorized(self):
        if self.client_address[0] not in NODES:self.send_error(403);return False
        return True
    def body(self,limit):
        size=int(self.headers.get('Content-Length','0'))
        if not 0<size<=limit:raise ValueError('The request body is empty or exceeds the exercise transfer budget.')
        body=self.rfile.read(size)
        if len(body)!=size:raise ValueError('The request body was not completely received.')
        return body
    def do_POST(self):
        if not self.authorized():return
        try:
            u=urlsplit(self.path);q=parse_qs(u.query);node=NODES[self.client_address[0]]
            if u.path=='/file':
                runid=valid_id(q['run_id'][0]);name=filename(q['name'][0]);body=self.body(12*1024*1024)
                if not name.endswith('.zip'):raise ValueError('Only ZIP evidence files are supported.')
                with STORE_LOCK:
                    path=ROOT/'runs'/runid/'files'/node/name;path.parent.mkdir(parents=True,exist_ok=True)
                    if path.exists():raise ValueError('This filename is already stored. Use a new filename.')
                    path.write_bytes(body)
                self.reply({'stored':name,'node':node,'bytes':len(body)});return
            data=json.loads(self.body(2*1024*1024))
            with STORE_LOCK:
                if u.path=='/facts':
                    if data.get('node')!=node:raise ValueError('The node name does not match the source address.')
                    data['received_utc']=utc();write(ROOT/'facts'/(node+'.json'),data)
                elif u.path=='/session':
                    runid=valid_id(data['run_id']);scenario=data['scenario'];delay=int(data.get('delay',90))
                    if scenario not in DURATIONS or not 30<=delay<=180:raise ValueError('The scenario or preparation delay is invalid.')
                    path=ROOT/'runs'/runid/'session.json'
                    if path.exists():raise ValueError('This run identifier is already in use. Choose a new one.')
                    profile=json.loads(PROFILE.read_text())
                    if profile['profile']!='baseline':raise ValueError('Restore the baseline configuration on web-waf before creating the session.')
                    start=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=delay)
                    data={'run_id':runid,'scenario':scenario,'created_utc':utc(),'start_utc':start.isoformat(),'end_utc':(start+datetime.timedelta(seconds=DURATIONS[scenario])).isoformat(),'duration_seconds':DURATIONS[scenario],'initial_profile':profile};write(path,data)
                elif u.path=='/record':
                    runid=valid_id(data['run_id']);kind=filename(data['kind'])
                    if data.get('node')!=node:raise ValueError('The node name does not match the source address.')
                    folder=ROOT/'runs'/runid/'records';folder.mkdir(parents=True,exist_ok=True)
                    if len(list(folder.glob('*.json')))>=100:raise ValueError('This run has reached its evidence record budget.')
                    data['received_utc']=utc();write(folder/(node+'-'+kind+'-'+str(time.time_ns())+'.json'),data)
                else:self.send_error(404);return
            self.reply(data)
        except (OSError,KeyError,ValueError,TypeError) as error:self.send_error(400,str(error))
    def do_GET(self):
        if not self.authorized():return
        try:
            u=urlsplit(self.path);q=parse_qs(u.query)
            if u.path=='/capture':self.capture(q);return
            if u.path=='/facts':self.reply([json.loads(p.read_text()) for p in sorted((ROOT/'facts').glob('*.json'))]);return
            runid=valid_id(q['run_id'][0]);base=ROOT/'runs'/runid
            if u.path=='/session':self.reply(json.loads((base/'session.json').read_text()))
            elif u.path=='/records':self.reply([json.loads(p.read_text()) for p in sorted((base/'records').glob('*.json'))])
            elif u.path=='/files':self.reply([{'node':p.parent.name,'name':p.name,'bytes':p.stat().st_size} for p in sorted((base/'files').glob('*/*.zip'))])
            elif u.path=='/file':
                node=q['node'][0]
                if node not in set(NODES.values()):raise ValueError('The node name is invalid.')
                body=(base/'files'/node/filename(q['name'][0])).read_bytes();self.send_response(200);self.send_header('Content-Type','application/zip');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            elif u.path=='/snapshot':self.reply({'run_id':runid,'checked_utc':utc(),'profile':json.loads(PROFILE.read_text()),'nginx_config':CONFIG.read_text()})
            else:self.send_error(404)
        except (OSError,KeyError,ValueError,TypeError) as error:self.send_error(400,str(error))
    def capture(self,q):
        if self.client_address[0] not in ('10.10.0.20','127.0.0.1'):self.send_error(403);return
        seconds=int(q.get('seconds',['30'])[0])
        if not 5<=seconds<=60:raise ValueError('Choose a packet capture lasting 5 to 60 seconds.')
        if not LOCK.acquire(blocking=False):self.send_error(409,'A packet capture is already running.');return
        try:
            interface=json.loads(subprocess.check_output(['ip','-j','route','get','10.10.0.40']))[0]['dev']
            with tempfile.TemporaryDirectory(prefix='crdos-capture-') as temp:
                path=Path(temp)/'capture.pcap'
                process=subprocess.Popen(['tcpdump','-U','-Z','root','-i',interface,'-s','512','-c','15000','-w',str(path),'tcp port 80'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                try:_,errors=process.communicate(timeout=seconds)
                except subprocess.TimeoutExpired:
                    process.send_signal(2)
                    try:_,errors=process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();_,errors=process.communicate(timeout=5)
                if process.returncode not in (0,-2) or not path.exists():raise RuntimeError('The packet capture failed: '+errors.decode(errors='replace')[-500:])
                body=path.read_bytes()
                if len(body)>8*1024*1024:raise RuntimeError('The packet capture exceeded its 8 MiB budget.')
                self.send_response(200);self.send_header('Content-Type','application/vnd.tcpdump.pcap');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        except (OSError,RuntimeError,subprocess.SubprocessError,KeyError) as error:self.send_error(500,str(error))
        finally:LOCK.release()
    def log_message(self,*args):pass
if __name__=='__main__':
    ROOT.mkdir(parents=True,exist_ok=True);ThreadingHTTPServer(('10.10.0.30',8081),Handler).serve_forever()
