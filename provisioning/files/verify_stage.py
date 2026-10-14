#!/usr/bin/env python3
"""Check selected technical prerequisites; the instructor assesses interpretation."""
import argparse,csv,datetime,json,subprocess,sys,urllib.request,urllib.parse
from pathlib import Path
import lab_api
ES='http://10.10.0.10:9200';KB='http://10.10.0.10:5601'
def require(condition,message):
    if not condition:raise ValueError(message)
def get(url,data=None):
    r=urllib.request.Request(url,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json','kbn-xsrf':'cr-dos'})
    with urllib.request.urlopen(r,timeout=20) as response:return json.load(response)
def stamp(value):
    d=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
    require(d.tzinfo is not None,'Use an explicit timezone in the recorded timestamp.');return d
def count(ids,filters):return get(ES+'/cr-dos-waf-*/_count',{'query':{'bool':{'filter':[{'terms':{'run_id':ids}}]+filters}}}).get('count',0)
def records_check(stage,task,runid,directory):
    path=Path(directory)/'records.json';require(path.is_file(),'First run evidence.py sync on SIEM to collect the original machine records.')
    records=json.loads(path.read_text());own=[r for r in records if r['run_id']==runid]
    data=lambda kind:[r['data'] for r in own if r['kind']==kind]
    captures=data('capture');loads=data('load');observers=data('observer');controls=data('control')
    captured=lambda label:any(c['label']==label and c['pcap']['packet_count']>0 and c['zeek_record_counts'].get('conn.log',0)>0 for c in captures)
    if stage=='CR-DOS-01':
        if task==1:
            facts=json.loads((Path(directory)/'node-facts.json').read_text());require({f['node'] for f in facts}==lab_api.NODES,'One or more working machines have not provided their node facts.')
            now=datetime.datetime.now(datetime.timezone.utc)
            require(all(-5<=(now-stamp(f['checked_utc'])).total_seconds()<120 for f in facts),'The machine facts are stale or the clocks disagree. Check clock synchronization and the cr-dos-facts service on the affected machines and collect again.')
            require(all(all(c['available'] for c in f['services']) and all(f['aliases'].values()) for f in facts),'A machine name or service check failed. Resolve it before proceeding.')
        else:require(captured('baseline'),'Collect a nonempty baseline packet capture and the Zeek connection records produced from it.')
    elif stage=='CR-DOS-02':
        require({'python','wrk'}<={d['tool'] for d in loads if d['completed']},'Complete both the bounded Python and wrk experiments using this run identifier.')
        require(any(d['completed'] and d['samples'] for d in observers),'Run the independent client on sensor and collect its completed observations.')
        require(captured('flood'),'Collect a nonempty packet capture during the HTTP flood.')
    elif stage=='CR-DOS-03':
        require(any(c['profile']['profile']=='protected' for c in controls),'Apply the protected configuration with --run-id so its actual time is recorded.')
        require(len([d for d in loads if d['completed']])>=2,'Collect completed tool results before and after protection.')
        require(len([d for d in observers if d['completed'] and d['samples']])>=2,'Collect independent client observations before and after protection.')
        if task>=2:require(captured('slow'),'Collect a separate nonempty capture during the slow-header experiment.')
        if task==3:
            measurements=[json.loads(p.read_text()) for p in Path(directory).glob('metrics-*.json')]
            require(len(measurements)>=2,'Save at least two measurements with actual UTC bounds using evidence.py metrics.')
            require(all(m['run_id']==runid and m['matched_requests']>0 for m in measurements),'A measurement is empty or belongs to another run. Check its actual UTC interval.')
    elif stage in ('CR-DOS-04','CR-DOS-06'):
        scenario='incident' if stage=='CR-DOS-04' else 'capstone';completed=[d for d in data('sequence') if d['completed'] and d['scenario']==scenario]
        require(bool(completed),'Complete the scheduled incident and inspect any failed tool result before proceeding.')
        sequence=completed[-1]
        require(any(d['completed'] and d['samples'] and stamp(d['end_utc'])>=stamp(sequence['scheduled_end_utc']) for d in observers),'Keep the sensor client running for the complete scheduled incident.')
        floods=[e['load'] for e in sequence['events'] if e.get('load') and e['load']['tool']=='python']
        require(any(c['profile']['profile']=='protected' and any(stamp(f['start_utc'])<=stamp(c['applied_utc'])<=stamp(f['end_utc']) for f in floods) for c in controls),'Apply and record protection while the flood is actually running. If you missed it, repeat within the active exercise using a new run identifier.')
        require(captured('flood'),'Preserve a nonempty packet capture from the flood interval.')
        if stage=='CR-DOS-06':
            require(sequence['duration_budget_seconds']==900,'The capstone must cover its complete fifteen-minute schedule.')
            require(any(any(s['profile']=='peak' for s in d['samples']) for d in observers),'The independent client record is missing the change in ordinary demand.')
            require(captured('slow'),'Preserve a separate packet capture during the slow-header interval.')
    elif stage=='CR-DOS-05':
        ids={runid+'-r'+str(i) for i in range(1,4)}
        for value in ids:
            part=[r for r in records if r['run_id']==value]
            require(any(r['kind']=='sequence' and r['data']['completed'] and r['data']['scenario']=='drill' for r in part),'The round '+value+' has not completed successfully.')
            require(any(r['kind']=='observer' and r['data']['completed'] and r['data']['samples'] for r in part),'The independent client observations are missing for '+value+'.')
        sessions=json.loads((Path(directory)/'sessions.json').read_text());require(ids<={s['run_id'] for s in sessions if s['initial_profile']['profile']=='baseline'},'Each round must start with a recorded baseline configuration.')
        tools={r['data']['tool'] for r in records if r['run_id'] in ids and r['kind']=='load' and r['data']['completed']}
        require({'python','wrk','slow'}<=tools,'Use Python, wrk and slowhttptest across the three separate rounds.')
        require(any(r['run_id'] in ids and r['kind']=='capture' and r['data']['label']=='slow' and r['data']['pcap']['packet_count']>0 for r in records),'The slow round needs its own packet capture.')
def check_csv(stage,path,runid):
    with path.open(newline='') as f:reader=csv.DictReader(f);rows=list(reader);fields=set(reader.fieldnames or [])
    if stage=='CR-DOS-05':
        required={'run_id','tool','attack_start_utc','detection_utc','control_utc','effective_mitigation_utc','attack_end_utc','recovery_utc','basis','evidence'}
        require(required<=fields,'Use the documented columns in rounds.csv; collect the automatic draft with evidence.py sync.')
        require(len(rows)==3 and {r['run_id'] for r in rows}=={runid+'-r'+str(i) for i in range(1,4)},'Include one row for each of the three distinct round identifiers.')
        for r in rows:
            start,end=stamp(r['attack_start_utc']),stamp(r['attack_end_utc']);require(end>=start,'A round end cannot precede its start.')
            if r['detection_utc']!='N/A':require(stamp(r['detection_utc'])>=start,'The recorded detection precedes this round. Check the reset and actual timestamps.')
            if r['effective_mitigation_utc']!='N/A':
                require(r['detection_utc']!='N/A','An effective mitigation time needs a documented detection time or an explained proactive action in your notes.')
                require(stamp(r['detection_utc'])<=stamp(r['effective_mitigation_utc'])<=end,'A claim of effective mitigation must be supported while the tool is still active.')
            require(r['basis'].strip() and r['evidence'].strip(),'Explain the observation basis and reference the evidence, including every N/A value.')
    else:
        require({'run_id','utc','event','basis','evidence'}<=fields,'Use run_id, utc, event, basis and evidence as the timeline columns.')
        require(len(rows)>=5,'Record at least five supported events in the incident timeline.')
        times=[stamp(r['utc']) for r in rows];require(times==sorted(times),'Arrange the timeline events in UTC order.')
        require(all(r['run_id']==runid and r['basis'] in ('observed-generator','observed-control','observed-trainee','estimated') and r['evidence'].strip() for r in rows),'Use the current run identifier and an explicit observation basis and evidence reference.')
def verify(stage,task,runid,directory):
    lab_api.validate_id(runid)
    if stage=='CR-DOS-05':require(len(runid)<=37,'The parent drill identifier must contain at most 37 characters.')
    spec=json.loads(Path(__file__).with_name('stage_checks.json').read_text())[stage];rule=spec['tasks'][task-1];path=Path(directory)/rule['file']
    require(path.is_file() and path.stat().st_size>=80,'Create the required note '+str(path)+' using your actual observations and interpretation.')
    text=path.read_text();require('TODO' not in text and '[WRITE' not in text,'Replace unfinished note placeholders with your own observations.')
    if task==1 and stage in ('CR-DOS-01','CR-DOS-06'):subprocess.run([sys.executable,str(Path(__file__).with_name('health.py'))],check=True)
    if not(stage=='CR-DOS-06' and task==1):
        ids=[runid+'-r'+str(i) for i in range(1,4)] if stage=='CR-DOS-05' else [runid]
        if not(stage=='CR-DOS-01' and task==1):require(count(ids,[{'term':{'phase':spec['phase']}}])>=5,'Fewer than five matching HTTP events are available. Check the traffic and allow Filebeat time to deliver its records.')
        records_check(stage,task,runid,directory)
    if path.suffix=='.csv':check_csv(stage,path,runid)
    if task==3 and spec['searches']:
        q=urllib.parse.urlencode({'type':'search','per_page':100,'search_fields':'title','search':stage+'-'+runid+'-*'})
        titles={x['attributes'].get('title','') for x in get(KB+'/api/saved_objects/_find?'+q).get('saved_objects',[])}
        missing=[stage+'-'+runid+'-'+name for name in spec['searches'] if stage+'-'+runid+'-'+name not in titles]
        require(not missing,'Save the missing Discover searches: '+', '.join(missing))
    if stage=='CR-DOS-03' and task==3:require(count([runid],[{'term':{'status':429}}])>0,'No rate-limit rejection was recorded. Repeat the protected comparison and check the HTTP results.')
    print(rule['passkey']);print('The selected technical checks passed. Enter the completion marker in the training page and submit your evidence to the LMS. The instructor will assess your interpretation and decisions separately.')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('stage',choices=['CR-DOS-'+str(i).zfill(2) for i in range(1,7)]);p.add_argument('task',type=int,choices=[1,2,3]);p.add_argument('--run-id',required=True);p.add_argument('--evidence',required=True);a=p.parse_args()
    try:verify(a.stage,a.task,a.run_id,a.evidence)
    except Exception as error:print('The check did not pass: '+str(error),file=sys.stderr);raise SystemExit(1)
