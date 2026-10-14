#!/usr/bin/env python3
"""Write your interpretation without pasting output from other terminals."""
import argparse,json,socket
from pathlib import Path
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--stage',choices=['CR-DOS-'+str(i).zfill(2) for i in range(1,7)],required=True);p.add_argument('--file',required=True);a=p.parse_args()
    if socket.gethostname().split('.')[0]!='siem':p.error('Write the assessment notes on the SIEM machine.')
    spec=json.loads(Path(__file__).with_name('stage_checks.json').read_text());allowed={x['file'] for x in spec[a.stage]['tasks']}|{'indicators.md','report-outline.md'}
    if a.file not in allowed or not a.file.endswith('.md'):p.error('Choose a Markdown note filename required by this exercise.')
    path=Path.home()/'evidence'/a.stage/a.file;path.parent.mkdir(parents=True,exist_ok=True)
    print('Explain your observations and decisions in your own words. End with a line containing only a dot. Your text will be appended to the note file.')
    lines=[]
    while True:
        try:line=input()
        except EOFError:break
        if line=='.':break
        lines.append(line)
    if lines:
        with path.open('a') as f:f.write('\n'.join(lines)+'\n')
        print('Your note was saved in '+str(path))
