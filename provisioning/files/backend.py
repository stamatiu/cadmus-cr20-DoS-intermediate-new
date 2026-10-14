#!/usr/bin/env python3
"""Small lab application with bounded expensive requests and a deliberate 500 endpoint."""
import argparse, json, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
SLOTS=threading.BoundedSemaphore(8)
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path=urlsplit(self.path).path
        code=200
        payload={'service':'CADMUS CR20 web application','path':path}
        if path=='/api/search':
            if not SLOTS.acquire(blocking=False): code=503; payload={'error':'lab worker capacity reached'}
            else:
                try: time.sleep(0.12); payload['results']=['training result']
                finally: SLOTS.release()
        elif path=='/demo-error': code=500; payload={'error':'deliberate teaching endpoint'}
        elif path not in ('/','/status','/about'): code=404; payload={'error':'unknown path'}
        body=json.dumps(payload).encode()
        self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError): pass
    def log_message(self,*args): pass
if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--port',type=int,default=8000); a=p.parse_args()
    ThreadingHTTPServer(('127.0.0.1',a.port),Handler).serve_forever()
