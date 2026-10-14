#!/usr/bin/env python3
"""Periodically collect real node facts rather than requiring transcription."""
import socket,time
import health,lab_api
def facts():
    names={}
    for name in sorted(lab_api.NODES):
        try:names[name]=socket.gethostbyname(name)
        except OSError:names[name]=None
    return {'node':socket.gethostname().split('.')[0],'checked_utc':lab_api.utc(),'aliases':names,'services':health.collect()}
if __name__=='__main__':
    while True:
        try:lab_api.call('/facts',facts())
        except (OSError,ValueError) as e:print('The node facts could not yet be delivered: '+str(e),flush=True)
        time.sleep(30)
