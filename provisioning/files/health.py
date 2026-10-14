#!/usr/bin/env python3
import argparse,json,urllib.request
import lab_api
CHECKS=[('Web application','http://10.10.0.30/status'),('Elasticsearch','http://10.10.0.10:9200/'),('Kibana','http://10.10.0.10:5601/api/status')]
def collect():
    results=[]
    for name,url in CHECKS:
        result={'service':name,'checked_utc':lab_api.utc(),'url':url,'available':False}
        try:
            with urllib.request.urlopen(url,timeout=5) as response:body=response.read();result['http_status']=response.status
            result['available']=result['http_status']==200 and (name!='Kibana' or json.loads(body)['status']['overall']['level']=='available')
        except Exception as error:result['error']=str(error)
        results.append(result)
    return results
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--json',action='store_true');a=p.parse_args();checks=collect()
    if a.json:print(json.dumps(checks,indent=2))
    else:
        for c in checks:print(c['service']+(' is available.' if c['available'] else ' is unavailable: '+c.get('error',str(c.get('http_status')))))
    raise SystemExit(0 if all(c['available'] for c in checks) else 1)
