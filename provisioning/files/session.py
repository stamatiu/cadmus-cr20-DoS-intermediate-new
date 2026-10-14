#!/usr/bin/env python3
import argparse,json
import lab_api
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--run-id',required=True);p.add_argument('--scenario',choices=['incident','drill','capstone'],required=True);p.add_argument('--delay',type=int,default=90);a=p.parse_args()
    if not 30<=a.delay<=180:p.error('Allow 30 to 180 seconds to prepare the consoles before the shared start.')
    lab_api.validate_id(a.run_id)
    s=lab_api.call('/session',{'run_id':a.run_id,'scenario':a.scenario,'delay':a.delay})
    print('Start the sensor observer and attacker helper before the UTC time shown below. They will wait for the same start automatically.')
    print(json.dumps(s,indent=2))
