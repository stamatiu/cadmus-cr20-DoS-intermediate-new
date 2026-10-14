#!/usr/bin/env python3
"""Preserve actual packets, Zeek tool output and capture coverage information."""
import argparse,datetime,json,os,socket,struct,subprocess,time,urllib.request,urllib.parse,zipfile
from pathlib import Path
import lab_api
def pcap_summary(path):
    body=path.read_bytes();modes={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
    if len(body)<24 or body[:4] not in modes:raise ValueError('The PCAP header is incomplete or unsupported.')
    endian,scale=modes[body[:4]];position=24;count=truncated=0;times=[]
    while position<len(body):
        if position+16>len(body):raise ValueError('A PCAP packet header is incomplete.')
        sec,frac,captured,original=struct.unpack(endian+'IIII',body[position:position+16]);position+=16
        if position+captured>len(body):raise ValueError('PCAP packet data is incomplete.')
        position+=captured;count+=1;truncated+=captured<original;times.append(sec+frac/scale)
    utc=lambda t:datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat()
    return {'packet_count':count,'truncated_packets':truncated,'first_packet_utc':utc(min(times)) if times else None,'last_packet_utc':utc(max(times)) if times else None,'packet_time_span_seconds':round(max(times)-min(times),3) if times else 0,'packet_cap_reached':count>=15000,'snaplen_bytes':struct.unpack(endian+'I',body[16:20])[0],'bytes':len(body)}
def capture(seconds,runid,label):
    lab_api.validate_id(runid);started=lab_api.utc();name=label+'-'+str(time.time_ns());folder=Path('/var/lib/cr-dos/zeek')/name
    subprocess.run(['sudo','install','-d','-m','0755','-o',str(os.getuid()),'-g',str(os.getgid()),str(folder)],check=True)
    with urllib.request.urlopen(lab_api.API+'/capture?seconds='+str(seconds),timeout=75) as response:(folder/'capture.pcap').write_bytes(response.read())
    image=Path('/opt/cr-dos/zeek-image.txt').read_text().strip()
    subprocess.run(['sudo','docker','run','--rm','--network','none','--read-only','--tmpfs','/tmp','--user',str(os.getuid())+':'+str(os.getgid()),'--entrypoint','/bin/sh','-v',str(folder)+':/work','-w','/work',image,'-c','exec zeek -C -r capture.pcap LogAscii::use_json=T'],check=True,timeout=120)
    counts={p.name:sum(1 for line in p.open() if line.strip()) for p in folder.glob('*.log')}
    report={'run_id':runid,'label':label,'start_utc':started,'end_utc':lab_api.utc(),'requested_seconds':seconds,'pcap':pcap_summary(folder/'capture.pcap'),'zeek_image':image,'zeek_record_counts':counts,'explanation':'Incomplete slow HTTP headers may produce connection records without completed HTTP records or a run label. Correlate them by source, target and actual UTC coverage.'}
    (folder/'capture-manifest.json').write_text(json.dumps(report,indent=2));archive=folder/(name+'.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.iterdir()):
            if p.is_file() and p!=archive:z.write(p,p.name)
    lab_api.call('/file?'+urllib.parse.urlencode({'run_id':runid,'name':archive.name}),raw=archive.read_bytes());lab_api.publish(runid,'capture',report)
    print('The real packet capture and Zeek tool output were saved in '+str(folder));print(json.dumps(report,indent=2));return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('seconds',type=int,nargs='?',default=30);p.add_argument('--run-id',required=True);p.add_argument('--label',choices=['baseline','flood','slow'],required=True);a=p.parse_args()
    if socket.gethostname().split('.')[0]!='sensor':p.error('Run the packet capture command on the sensor machine.')
    if not 5<=a.seconds<=60:p.error('Choose a packet capture lasting 5 to 60 seconds.')
    capture(a.seconds,a.run_id,a.label)
