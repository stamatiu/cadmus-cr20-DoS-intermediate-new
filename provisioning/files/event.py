#!/usr/bin/env python3
import argparse,json
import lab_api
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--run-id',required=True);p.add_argument('--event',choices=['detection','effective-mitigation','recovery','escalation'],required=True);p.add_argument('--note',required=True);a=p.parse_args()
    print(json.dumps(lab_api.publish(a.run_id,'event',{'event':a.event,'utc':lab_api.utc(),'note':a.note}),indent=2))
