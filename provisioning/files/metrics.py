#!/usr/bin/env python3
import argparse,datetime,json,urllib.request
ES='http://10.10.0.10:9200'
def query(index,payload):
    r=urllib.request.Request(ES+'/'+index+'/_search',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(r,timeout=20) as response:return json.load(response)
def percentile():return {'percentiles':{'field':'request_time','percents':[50,95]}}
def clients(extra=None):
    filters=[{'term':{'remote_addr':'10.10.0.20'}},{'term':{'phase':'legitimate'}},{'term':{'uri':'/api/search'}}]+(extra or [])
    return {'filter':{'bool':{'filter':filters}},'aggs':{'responses':{'terms':{'field':'status','size':12}},'successful':{'filter':{'term':{'status':200}},'aggs':{'latency':percentile()}},'rejected':{'filter':{'term':{'status':429}}}}}
def metrics(runid,minutes=240,start=None,end=None):
    if (start is None)!=(end is None):raise ValueError('Provide both the actual UTC start and end of the measurement interval.')
    if start:
        first=datetime.datetime.fromisoformat(start.replace('Z','+00:00'));last=datetime.datetime.fromisoformat(end.replace('Z','+00:00'))
        if first.tzinfo is None or last.tzinfo is None or last<=first:raise ValueError('Use increasing timestamps with an explicit timezone.')
    if not 1<=minutes<=1440:raise ValueError('The fallback interval must be between 1 and 1440 minutes.')
    bounds={'gte':start or 'now-'+str(minutes)+'m','lte':end or 'now'}
    aggs={'status_codes':{'terms':{'field':'status','size':12}},'clients':{'terms':{'field':'remote_addr','size':10}},'paths':{'terms':{'field':'uri','size':10}},'all_response_latency':percentile(),'legitimate_search':clients(),'normal_demand':clients([{'term':{'client_profile':'normal'}}]),'peak_demand':clients([{'term':{'client_profile':'peak'}}]),'attack':{'filter':{'bool':{'filter':[{'term':{'remote_addr':'10.10.0.40'}},{'term':{'phase':'attack'}}]}},'aggs':{'responses':{'terms':{'field':'status','size':12}},'rate_rejected':{'filter':{'term':{'status':429}}}}},'per_10_seconds':{'date_histogram':{'field':'@timestamp','fixed_interval':'10s','min_doc_count':0}},'limiting':{'terms':{'field':'limit_req_status','size':10}}}
    result=query('cr-dos-waf-*',{'size':0,'track_total_hits':True,'query':{'bool':{'filter':[{'term':{'run_id':runid}},{'range':{'@timestamp':bounds}}]}},'aggs':aggs})
    data=result.get('aggregations',{});summary={}
    for key in ('legitimate_search','normal_demand','peak_demand'):
        bucket=data.get(key,{});total=bucket.get('doc_count',0);successful=bucket.get('successful',{});rejected=bucket.get('rejected',{}).get('doc_count',0)
        summary[key]={'completed_http_requests':total,'success_http200':successful.get('doc_count',0),'rejected_http429':rejected,'http429_percentage':round(100*rejected/total,3) if total else None,'successful_latency_seconds':successful.get('latency',{}).get('values',{})}
    return {'run_id':runid,'time_filter':bounds,'latency_unit':'seconds','histogram_bucket_unit':'requests per 10 seconds','matched_requests':result.get('hits',{}).get('total',{}).get('value',0),'client_summary':summary,'aggregations':data,'limitations':'Server records cover completed HTTP requests. Use the independent client samples for transport failures and success over all attempts. All-response latency includes rejections. Successful latency filters the sensor source, legitimate phase, search path and HTTP 200. An attacker HTTP 200 alone does not demonstrate harmful residual traffic.'}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--run-id',required=True);p.add_argument('--minutes',type=int,default=240);p.add_argument('--from-utc');p.add_argument('--to-utc');a=p.parse_args();print(json.dumps(metrics(a.run_id,a.minutes,a.from_utc,a.to_utc),indent=2))
