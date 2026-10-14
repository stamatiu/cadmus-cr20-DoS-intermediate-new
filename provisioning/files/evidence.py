#!/usr/bin/env python3
"""Collect original machine output; the trainee supplies the interpretation."""
import argparse,csv,io,json,re,socket,time,urllib.parse,zipfile
from pathlib import Path
import lab_api,metrics
def write_observations(records,path):
    lines=['# Collected observations','', 'These summaries use the original machine records. Explain their meaning in your own notes and refer to the actual intervals. They do not supply an incident conclusion.','']
    for r in records:
        d=r['data'];kind=r['kind'];lines+=['## '+r['run_id']+' '+r['node']+' '+kind,'']
        if kind in ('observer','traffic'):
            lines+=['Actual interval: '+str(d.get('start_utc','not recorded'))+' to '+str(d.get('end_utc','not recorded')),'']
            groups=d.get('by_client_profile') or {d.get('profile','client'):{'requests':len(d.get('samples',[])),'status_counts':d.get('status_counts',{}),'successful_latency':d.get('successful_latency',{})}}
            for name,g in sorted(groups.items()):
                total=g['requests'];counts=g['status_counts'];ok=counts.get('200',0);rejected=counts.get('429',0);failed=counts.get('0',0)
                lines+=['Client profile: '+name,'Attempts: '+str(total),'Recorded outcomes: '+json.dumps(counts),'Success over all attempts: '+(str(round(100*ok/total,3))+'%' if total else 'N/A'),'HTTP 429 over all attempts: '+(str(round(100*rejected/total,3))+'%' if total else 'N/A'),'Transport failures: '+str(failed),'Successful response time in seconds: '+json.dumps(g.get('successful_latency',{})),'']
        elif kind=='load':lines+=['Tool: '+d['tool'],'Actual interval: '+d['start_utc']+' to '+d['end_utc'],'Completed: '+str(d['completed']),'Original result: '+json.dumps({k:v for k,v in d.items() if k not in ('stdout','stderr')},sort_keys=True),'']
        elif kind=='control':lines+=['Applied UTC: '+d['applied_utc'],'Applied configuration: '+json.dumps(d['profile']),'']
        elif kind=='capture':lines+=['Capture label: '+d['label'],'Actual packet coverage: '+str(d['pcap']['first_packet_utc'])+' to '+str(d['pcap']['last_packet_utc']),'Packet information: '+json.dumps(d['pcap']),'Zeek tool record counts: '+json.dumps(d['zeek_record_counts']),'']
        elif kind=='event':lines+=['Recorded UTC: '+d['utc'],'Event: '+d['event'],'Trainee observation: '+d['note'],'']
        elif kind=='sequence':lines+=['Scenario: '+d['scenario'],'Completed: '+str(d['completed']),'Scheduled interval: '+d['scheduled_start_utc']+' to '+d['scheduled_end_utc'],'']
    path.write_text('\n'.join(lines))
def extract(body,directory):
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        if len(z.infolist())>100 or sum(i.file_size for i in z.infolist())>32*1024*1024:raise ValueError('The evidence ZIP exceeds its extraction budget.')
        for i in z.infolist():
            target=(directory/i.filename).resolve()
            if not target.is_relative_to(directory.resolve()) or i.is_dir() or i.filename.startswith('/') or ((i.external_attr>>16)&0o170000)==0o120000:raise ValueError('The evidence ZIP contains an unsafe path.')
        z.extractall(directory)
def sync(stage,runid):
    lab_api.validate_id(runid)
    if stage=='CR-DOS-05' and len(runid)>37:raise ValueError('Use at most 37 characters for the parent drill identifier.')
    directory=Path.home()/'evidence'/stage
    previous=directory/'collection.json'
    if previous.exists():
        prior=json.loads(previous.read_text()).get('run_id')
        if prior and prior!=runid:
            history=directory.parent/'previous';history.mkdir(parents=True,exist_ok=True)
            directory.rename(history/(stage+'_'+prior+'_'+str(time.time_ns())))
    directory.mkdir(parents=True,exist_ok=True)
    runs=[runid+'-r'+str(i) for i in range(1,4)] if stage=='CR-DOS-05' else [runid];records=[];sessions=[]
    for value in runs:
        q=urllib.parse.urlencode({'run_id':value});part=lab_api.call('/records?'+q);records.extend(part);folder=directory/'results'/value;folder.mkdir(parents=True,exist_ok=True)
        for i,r in enumerate(part):(folder/(r['node']+'-'+r['kind']+'-'+str(i)+'.json')).write_text(json.dumps(r,indent=2))
        try:
            s=lab_api.session(value);sessions.append(s);(folder/'session.json').write_text(json.dumps(s,indent=2))
        except OSError:pass
        for item in lab_api.call('/files?'+q):
            if item['node']!='sensor':continue
            body=lab_api.call('/file?'+urllib.parse.urlencode({'run_id':value,'node':item['node'],'name':item['name']}));out=directory/'captures'/value/Path(item['name']).stem;out.mkdir(parents=True,exist_ok=True);extract(body,out)
    write_observations(records,directory/'observations.md')
    facts=lab_api.call('/facts');(directory/'node-facts.json').write_text(json.dumps(facts,indent=2))
    lines=['# Actual machine and service checks','', 'Collection UTC: '+lab_api.utc(),'','Review the timestamps and any unavailable service. These values come from the machines; they are not example observations.','']
    for fact in facts:
        lines+=['## '+fact['node'],'Check UTC: '+fact['checked_utc'],'Name resolution: '+json.dumps(fact['aliases'])]
        lines += [c['service']+': '+('available' if c['available'] else 'unavailable')+'; HTTP '+str(c.get('http_status','unknown'))+'; UTC '+c['checked_utc'] for c in fact['services']]
        lines.append('')
    (directory/'health.md').write_text('\n'.join(lines))
    snapshot=lab_api.call('/snapshot?'+urllib.parse.urlencode({'run_id':runid}));(directory/'waf-snapshot.json').write_text(json.dumps(snapshot,indent=2));(directory/'nginx-final.conf').write_text(snapshot['nginx_config'])
    (directory/'records.json').write_text(json.dumps(records,indent=2));(directory/'sessions.json').write_text(json.dumps(sessions,indent=2))
    events=[]
    for r in records:
        d=r['data']
        if r['kind']=='sequence':
            for e in d['events']:
                events.append([r['run_id'],e['start_utc'],e['phase']+'-slot-start','observed-generator','Original sequence record'])
                if e.get('load'):
                    events.append([r['run_id'],e['load']['start_utc'],e['load']['tool']+'-tool-start','observed-generator','Original tool record'])
                    events.append([r['run_id'],e['load']['end_utc'],e['load']['tool']+'-tool-end','observed-generator','Original tool record'])
        elif r['kind']=='control':events.append([r['run_id'],d['applied_utc'],'control-applied','observed-control',json.dumps(d['profile'])])
        elif r['kind']=='event':events.append([r['run_id'],d['utc'],d['event'],'observed-trainee',d['note']])
    with (directory/'collected-events.csv').open('w',newline='') as f:
        writer=csv.writer(f);writer.writerow(['run_id','utc','event','basis','evidence']);writer.writerows(sorted(events,key=lambda e:e[1]))
    if stage in ('CR-DOS-04','CR-DOS-06') and not (directory/'timeline.csv').exists():(directory/'timeline.csv').write_bytes((directory/'collected-events.csv').read_bytes())
    if stage=='CR-DOS-05' and not (directory/'rounds.csv').exists():
        with (directory/'rounds.csv').open('w',newline='') as f:
            writer=csv.writer(f);writer.writerow(['run_id','tool','attack_start_utc','detection_utc','control_utc','effective_mitigation_utc','attack_end_utc','recovery_utc','basis','evidence'])
            for value in runs:
                part=[r for r in records if r['run_id']==value];loads=[r['data'] for r in part if r['kind']=='load' and r['data']['completed']]
                if not loads:continue
                load=loads[-1];observations=[r['data'] for r in part if r['kind']=='event']
                first=lambda name:min([d['utc'] for d in observations if d['event']==name],default='N/A')
                applied=[r['data']['applied_utc'] for r in part if r['kind']=='control' and r['data']['profile']['profile']=='protected']
                writer.writerow([value,load['tool'],load['start_utc'],first('detection'),min(applied) if applied else 'N/A',first('effective-mitigation'),load['end_utc'],first('recovery'),'observed; explain any N/A in metrics.md','results/'+value+'/'])
    (directory/'collection.json').write_text(json.dumps({'stage':stage,'run_id':runid,'collected_utc':lab_api.utc(),'records':len(records),'runs':runs},indent=2))
    print('The original machine records and packet files were collected in '+str(directory)+'. Write your explanation in the note files requested by the exercise.');return directory
def export(stage,runid):
    directory=sync(stage,runid);folder=Path.home()/'exports';folder.mkdir(exist_ok=True);archive=folder/(stage+'_'+runid+'.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(directory.rglob('*')):
            if p.is_file():z.write(p,p.relative_to(directory))
    if archive.stat().st_size<=12*1024*1024:lab_api.call('/file?'+urllib.parse.urlencode({'run_id':runid,'name':archive.stem+'-'+str(time.time_ns())+'.zip'}),raw=archive.read_bytes())
    else:print('This ZIP exceeds the optional internal copy budget. Download it directly from SIEM through the approved file-transfer route.')
    print('Your evidence ZIP is '+str(archive)+'. Download it through the organizer-tested route and submit it to the LMS before the exercise countdown expires.');return archive
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['sync','export','metrics']);p.add_argument('--stage',choices=['CR-DOS-'+str(i).zfill(2) for i in range(1,7)],required=True);p.add_argument('--run-id',required=True);p.add_argument('--label',default='measurement');p.add_argument('--from-utc');p.add_argument('--to-utc');a=p.parse_args()
    if socket.gethostname().split('.')[0]!='siem':p.error('Collect, measure and export the evidence on SIEM.')
    if a.action=='sync':sync(a.stage,a.run_id)
    elif a.action=='export':export(a.stage,a.run_id)
    else:
        if not a.from_utc or not a.to_utc:p.error('Provide the actual UTC start and end of this measurement interval.')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',a.label):p.error('Use a short label containing letters, digits, hyphens or underscores.')
        directory=Path.home()/'evidence'/a.stage;directory.mkdir(parents=True,exist_ok=True);report=metrics.metrics(a.run_id,240,a.from_utc,a.to_utc);(directory/('metrics-'+a.label+'.json')).write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
