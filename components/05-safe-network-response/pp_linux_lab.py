"""Fixed, disconnected network namespaces; installed root-owned, never model code."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import subprocess
import time
import uuid
from pathlib import Path
from pp_response_operations import block_spec, command_plan, TC, HANDLE

NS = {'source': 'pp-lab-source', 'control': 'pp-lab-control',
      'service': 'pp-lab-service', 'switch': 'pp-lab-switch'}
IPS = {'source': '10.77.0.20', 'control': '10.77.0.30', 'service': '10.77.0.10'}
IP = '/usr/sbin/ip'
IPTABLES = '/usr/sbin/iptables'
PYTHON = '/usr/bin/python3'
TCPDUMP = '/usr/bin/tcpdump'

SERVER = '''import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.77.0.10",8080));s.listen(16)
def serve(c):
 c.settimeout(8)
 try:
  request=c.recv(1024)
  body=b"P"*131072 if request.startswith(b"GET /payload ") else b"PacketPilot\\n"
  c.sendall(b"HTTP/1.0 200 OK\\r\\nContent-Length: "+str(len(body)).encode()+b"\\r\\n\\r\\n"+body)
 except OSError: pass
 finally: c.close()
while True:
 c,a=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
'''
PROBE = '''import socket,sys
try:
 s=socket.create_connection(("10.77.0.10",8080),timeout=0.7);s.settimeout(0.7)
 s.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n");r=s.recv(1024);s.close()
 sys.exit(0 if r.startswith(b"HTTP/1.0 200") else 2)
except OSError: sys.exit(1)
'''
TRANSFER = '''import socket,time,json,hashlib
start=time.monotonic()
with socket.create_connection(("10.77.0.10",8080),timeout=8) as s:
 s.settimeout(8);s.sendall(b"GET /payload HTTP/1.0\\r\\n\\r\\n");chunks=[]
 while True:
  raw=s.recv(16384)
  if not raw: break
  chunks.append(raw)
response=b"".join(chunks);header,body=response.split(b"\\r\\n\\r\\n",1)
elapsed=time.monotonic()-start
if not header.startswith(b"HTTP/1.0 200") or body!=b"P"*131072: raise ValueError("Incomplete lab transfer")
print(json.dumps(dict(bytes=len(body),seconds=elapsed,kbit_per_second=len(body)*8/elapsed/1000,
                     body_sha256=hashlib.sha256(body).hexdigest(),complete=True)))
'''


class LinuxLab:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.manifest_path = self.directory / 'lab.json'
        self.server = None

    def run(self, argv, check=True):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=12,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
        if check and result.returncode:
            raise RuntimeError(f'Fixed lab command failed ({result.returncode}): {result.stderr.strip()[:180]}')
        return result

    def inside(self, role, argv, check=True):
        return self.run([IP, 'netns', 'exec', NS[role], *argv], check)

    def setup(self):
        existing = {line.split()[0] for line in self.run([IP, 'netns', 'list']).stdout.splitlines()}
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if self.manifest_path.exists():
            previous = json.loads(self.manifest_path.read_text())
            if previous.get('boot_id') != boot_id and not existing.intersection(NS.values()):
                self.manifest_path.rename(self.directory / ('lab-history-'+previous['generation']+'.json'))
        if self.manifest_path.exists():
            self.manifest = json.loads(self.manifest_path.read_text())
            self.check()
        else:
            if existing.intersection(NS.values()):
                raise RuntimeError('Reserved namespace name already exists; refusing to adopt or delete it.')
            root_links = {item['ifname'] for item in json.loads(self.run([IP, '-j', 'link']).stdout)}
            reserved = {f'ppv{i}{side}' for i in range(3) for side in ('a', 'b')}
            if root_links & reserved:
                raise RuntimeError('Reserved veth name exists; refusing to touch it.')
            for name in NS.values():
                self.run([IP, 'netns', 'add', name])
                self.run([IP, '-n', name, 'link', 'set', 'lo', 'up'])
            self.run([IP, '-n', NS['switch'], 'link', 'add', 'br0', 'type', 'bridge'])
            self.run([IP, '-n', NS['switch'], 'link', 'set', 'br0', 'up'])
            for i, role in enumerate(('source', 'control', 'service')):
                a, b = f'ppv{i}a', f'ppv{i}b'
                self.run([IP, 'link', 'add', a, 'type', 'veth', 'peer', 'name', b])
                self.run([IP, 'link', 'set', a, 'netns', NS[role]])
                self.run([IP, 'link', 'set', b, 'netns', NS['switch']])
                self.run([IP, '-n', NS[role], 'link', 'set', a, 'name', 'eth0'])
                self.run([IP, '-n', NS[role], 'addr', 'add', IPS[role]+'/24', 'dev', 'eth0'])
                self.run([IP, '-n', NS[role], 'link', 'set', 'eth0', 'up'])
                self.run([IP, '-n', NS['switch'], 'link', 'set', b, 'master', 'br0'])
                self.run([IP, '-n', NS['switch'], 'link', 'set', b, 'up'])
            self.manifest = {'generation': str(uuid.uuid4()), 'created_at': time.time(), 'boot_id': boot_id,
                             'namespace_inodes': {role: os.stat('/run/netns/'+name).st_ino for role, name in NS.items()}}
            self.manifest_path.write_text(json.dumps(self.manifest, indent=2))
        self.server = subprocess.Popen([IP, 'netns', 'exec', NS['service'], PYTHON, '-u', '-c', SERVER],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.25)
        if self.server.poll() is not None:
            raise RuntimeError('The isolated service could not start; refusing to use an unknown listener.')

    def check(self):
        for role, name in NS.items():
            if os.stat('/run/netns/'+name).st_ino != self.manifest['namespace_inodes'][role]:
                raise RuntimeError('Namespace identity changed.')
            links = {item['ifname'] for item in json.loads(self.run([IP, '-n', name, '-j', 'link']).stdout)}
            expected = {'lo', 'br0', 'ppv0b', 'ppv1b', 'ppv2b'} if role == 'switch' else {'lo', 'eth0'}
            if links != expected:
                raise RuntimeError('Unexpected lab interface; isolation must be reviewed.')
            routes = json.loads(self.run([IP, '-n', name, '-j', 'route']).stdout)
            if any(r.get('dst') == 'default' or r.get('gateway') for r in routes):
                raise RuntimeError('Unexpected gateway/default route in disconnected lab.')
            if role in IPS:
                addresses = json.loads(self.run([IP, '-n', name, '-j', '-4', 'addr', 'show', 'dev', 'eth0']).stdout)
                if [a['local'] for a in addresses[0]['addr_info']] != [IPS[role]]:
                    raise RuntimeError('Lab address mapping changed.')

    def status(self):
        self.check()
        return {'available': True, 'generation': self.manifest['generation'],
                'namespaces': NS, 'addresses': IPS, 'service_port': 8080,
                'isolation': 'No external interface, gateway or default route. Host firewall untouched.'}

    def probe(self):
        self.check()
        return {role+'_reachable': self.inside(role, [PYTHON, '-c', PROBE], False).returncode == 0
                for role in ('source', 'control')}

    @staticmethod
    def specification(action_id):
        return block_spec(action_id)

    def rule(self, action_id):
        spec = self.specification(action_id)
        result = self.inside('service', [IPTABLES, '-w', '2', '-C', 'INPUT', *spec], False)
        if result.returncode not in (0, 1):
            raise RuntimeError('Cannot determine rule state.')
        return {'present': result.returncode == 0,
                'rules': self.inside('service', [IPTABLES, '-w', '2', '-nvxL', 'INPUT']).stdout}

    def block(self, action_id):
        self.check()
        if self.rule(action_id)['present']:
            raise RuntimeError('Duplicate rule.')
        self.inside('service', [IPTABLES, '-w', '2', '-I', 'INPUT', '1', *self.specification(action_id)])
        return self.rule(action_id)

    def unblock(self, action_id):
        self.check()
        if self.rule(action_id)['present']:
            self.inside('service', [IPTABLES, '-w', '2', '-D', 'INPUT', *self.specification(action_id)])

    def measure(self):
        self.check()
        return {role: json.loads(self.inside(role, [PYTHON, '-c', TRANSFER]).stdout)
                for role in ('source', 'control')}

    def rate_identity(self, action_id):
        block_spec(action_id)  # Validate the canonical identifier before any command.
        self.check()
        owner_path = self.directory / 'rate-owner.json'
        owner = json.loads(owner_path.read_text()) if owner_path.exists() else None
        qdiscs = json.loads(self.inside('service', [TC, '-j', 'qdisc', 'show', 'dev', 'eth0']).stdout)
        root = [q for q in qdiscs if q.get('root')]
        ours = [q for q in root if q.get('handle') == HANDLE and q.get('kind') == 'htb']
        if owner and (owner['action_id'] != action_id or owner['generation'] != self.manifest['generation']):
            raise RuntimeError('The shaper belongs to a different action or lab generation.')
        if any(q.get('kind') != 'noqueue' for q in root) and (not owner or not ours):
            raise RuntimeError('Unknown lab root qdisc; refusing to replace or delete it.')
        return dict(present=bool(ours), owned=bool(owner), qdiscs=qdiscs)

    def rate_state(self, action_id):
        state = self.rate_identity(action_id)
        # Ubuntu's tc HTB class inspection emits text even with -j. Retain it
        # honestly; rollback must not depend on optional detail decoding.
        state['classes'] = {'format':'tc_text','output':self.inside('service', [TC, '-s', 'class', 'show', 'dev', 'eth0']).stdout} if state['present'] else []
        state['filters'] = json.loads(self.inside('service', [TC, '-j', 'filter', 'show', 'dev', 'eth0', 'parent', HANDLE]).stdout.strip() or '[]') if state['present'] else []
        return state

    def rate_limit(self, action_id, parameters):
        state = self.rate_state(action_id)
        if state['present'] or state['owned']:
            raise RuntimeError('A rate-limit operation is already present.')
        # Durable ownership is written BEFORE the first change so a partial apply can recover.
        path = self.directory / 'rate-owner.json'
        with path.open('w') as stream:
            json.dump(dict(action_id=action_id, generation=self.manifest['generation']), stream)
            stream.flush(); os.fsync(stream.fileno())
        for argv in command_plan(parameters, action_id)['apply_argv']:
            self.run(argv)
        return self.rate_state(action_id)

    def unrate(self, action_id):
        state = self.rate_identity(action_id)
        if state['present']:
            self.inside('service', [TC, 'qdisc', 'del', 'dev', 'eth0', 'root', 'handle', HANDLE])
        path = self.directory / 'rate-owner.json'
        if state['owned']:
            path.unlink()  # One exact broker-owned marker; never a caller-selected path.

    def capture(self):
        self.check()
        capture_id = str(uuid.uuid4())
        folder = self.directory / 'captures'
        folder.mkdir(exist_ok=True, mode=0o700)
        path = folder / (capture_id+'.pcap')
        with (folder / (capture_id+'.log')).open('wb') as log:
            process = subprocess.Popen([IP, 'netns', 'exec', NS['service'], TCPDUMP,
                                        '--immediate-mode', '-U', '-i', 'eth0', '-s', '0', '-w', str(path), 'tcp', 'port', '8080'],
                                       stdout=subprocess.DEVNULL, stderr=log)
            try:
                time.sleep(0.4)
                if process.poll() is not None:
                    raise RuntimeError('Lab capture could not start.')
                for _ in range(3):
                    self.probe()
                time.sleep(0.3)
            finally:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        raw = path.read_bytes()
        if not 24 < len(raw) <= 1_048_576:
            raise RuntimeError('Lab capture was empty or too large.')
        meta = {'capture_id': capture_id, 'capture_sha256': hashlib.sha256(raw).hexdigest(),
                'generation': self.manifest['generation'], 'recorded_at_epoch': time.time(),
                'scope': 'Current isolated lab TCP service test; known authorised traffic, not an attack.'}
        (folder / (capture_id+'.json')).write_text(json.dumps(meta, indent=2))
        return meta | {'pcap_base64': base64.b64encode(raw).decode()}

    def validate_capture(self, capture_id, digest):
        if type(capture_id) is not str or str(uuid.UUID(capture_id)) != capture_id:
            raise ValueError('A broker-issued current lab capture is required.')
        self.check()
        path = self.directory / 'captures' / (capture_id+'.json')
        if not path.is_file():
            raise ValueError('Unknown lab capture; uploaded/offline evidence cannot authorise execution.')
        meta = json.loads(path.read_text())
        if (meta['capture_sha256'] != digest or meta['generation'] != self.manifest['generation']
                or not 0 <= time.time()-meta['recorded_at_epoch'] <= 600):
            raise ValueError('Capture is stale, mismatched or from another lab generation.')
        return meta
