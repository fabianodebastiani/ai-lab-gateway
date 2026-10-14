#!/usr/bin/env python3
"""Local root-only broker v0.2; not exposed over MCP."""
import argparse,json,os,secrets,subprocess,sys,tempfile,time
from pathlib import Path
S=Path('/var/lib/ai-lab-privilege-broker')
DB=S/'grants.json'
AUD=S/'audit.jsonl'
OPS={'gateway-service-status':['/usr/bin/systemctl','is-active','ai-lab-gateway'],'gateway-service-enabled':['/usr/bin/systemctl','is-enabled','ai-lab-gateway']}
def audit(action,result,gid=None):
 with AUD.open('a') as f:f.write(json.dumps({'time':int(time.time()),'action':action,'result':result,'grant_id':gid})+'\n')
def load():
 if not DB.exists():return {}
 d=json.loads(DB.read_text())
 if not isinstance(d,dict):raise ValueError('invalid db')
 return d
def save(d):
 fd,p=tempfile.mkstemp(dir=S,prefix='.grant-')
 try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'w') as f:
   json.dump(d,f);f.flush();os.fsync(f.fileno())
  os.replace(p,DB)
 finally:
  if os.path.exists(p):os.unlink(p)
def main():
 if os.geteuid()!=0:raise PermissionError('root required')
 S.mkdir(mode=0o700,exist_ok=True);os.chmod(S,0o700)
 AUD.touch(exist_ok=True);os.chmod(AUD,0o600)
 p=argparse.ArgumentParser();sub=p.add_subparsers(dest='cmd',required=True)
 sub.add_parser('status')
 q=sub.add_parser('issue');q.add_argument('operation',choices=sorted(OPS));q.add_argument('--ttl',type=int,default=1800)
 for n in ('execute','revoke'):
  q=sub.add_parser(n);q.add_argument('grant_id')
 a=p.parse_args();d=load()
 if a.cmd=='status':
  audit('status','ok')
  print(json.dumps({'version':'0.2-local','grant_count':len(d),'operations':sorted(OPS),'remote_approval_enabled':False,'arbitrary_shell_enabled':False}));return 0
 if a.cmd=='issue':
  if not 1<=a.ttl<=86400:audit('issue','denied');return 77
  gid=secrets.token_urlsafe(24)
  d[gid]={'operation':a.operation,'expires_at':int(time.time())+a.ttl,'state':'active','issued_by':'local-root-bootstrap'}
  save(d);audit('issue','ok',gid)
  print(json.dumps({'grant_id':gid,'operation':a.operation,'expires_at':d[gid]['expires_at']}));return 0
 g=d.get(a.grant_id)
 if not g:audit(a.cmd,'denied');return 77
 if a.cmd=='revoke':
  g['state']='revoked';save(d);audit('revoke','ok',a.grant_id);print('revoked');return 0
 if g.get('state')!='active' or int(time.time())>=g.get('expires_at',0) or g.get('operation') not in OPS:
  audit('execute','denied',a.grant_id);return 77
 g['state']='consumed';save(d)
 r=subprocess.run(OPS[g['operation']],shell=False,capture_output=True,text=True,timeout=15)
 audit('execute','ok' if r.returncode==0 else 'failed',a.grant_id)
 sys.stdout.write(r.stdout);sys.stderr.write(r.stderr);return r.returncode
if __name__=='__main__':
 try:sys.exit(main())
 except (PermissionError,ValueError,subprocess.TimeoutExpired) as e:
  print('DENIED:',type(e).__name__,file=sys.stderr);sys.exit(77)
