"""Administrator read-only network snapshot for controlled-response verification."""
import hashlib
import json
import os
import subprocess
from datetime import datetime,timezone
from pathlib import Path

if os.geteuid()!=0: raise SystemExit('Run as administrator for firewall visibility.')
commands={
 'root_addresses':['/usr/sbin/ip','-j','addr'],
 'root_routes':['/usr/sbin/ip','-j','route'],
 'root_firewall':['/usr/sbin/iptables-save'],
 'namespaces':['/usr/sbin/ip','netns','list'],
 'service_rules':['/usr/sbin/ip','netns','exec','pp-lab-service','/usr/sbin/iptables-save'],
}
record={'at':datetime.now(timezone.utc).isoformat(),'commands':{}}
for name,command in commands.items():
 p=subprocess.run(command,capture_output=True,text=True,timeout=10,check=True)
 record['commands'][name]={'argv':command,'stdout':p.stdout,'sha256':hashlib.sha256(p.stdout.encode()).hexdigest()}
folder=Path('/home/capstone/packetpilot-linux-response/network-evidence');folder.mkdir(parents=True,exist_ok=True)
path=folder/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'.json')
with path.open('x') as output:json.dump(record,output,indent=2)
os.chmod(path,0o644)
print(str(path))
