"""Bounded asynchronous capture of the existing isolated service only."""
import base64
import hashlib
import json
import signal
import subprocess
import threading
import time
import uuid
from pp_linux_lab import IP, NS, TCPDUMP

class CaptureSessions:
    def __init__(self,lab):
        self.lab=lab;self.lock=threading.RLock();self.jobs={};self.active=None
    def start(self,duration_seconds):
        if type(duration_seconds)is not int or not 2<=duration_seconds<=20:raise ValueError('Capture duration must be an integer from2to20seconds.')
        with self.lock:
            if self.active:raise ValueError('A capture is already collecting.')
            self.lab.check();identity=str(uuid.uuid4());folder=self.lab.directory/'captures';folder.mkdir(mode=0o700,exist_ok=True)
            path=folder/(identity+'.pcap');log=folder/(identity+'.log')
            job=dict(id=identity,status='starting',duration_seconds=duration_seconds,started_at_epoch=time.time(),
                observation_point='pp-lab-service eth0',filter='tcp port8080',packet_limit=5000,byte_limit=1048576,
                profile='Fixed lab service health checks; authorised requests are generated while collecting.')
            self.jobs[identity]=dict(public=job,stop=threading.Event(),cancel=False,path=path,log=log)
            self.active=identity
            self.jobs[identity]['thread']=threading.Thread(target=self.collect,args=(identity,),daemon=True)
            self.jobs[identity]['thread'].start()
            return dict(job)
    def collect(self,identity):
        job=self.jobs[identity];process=None
        try:
            with job['log'].open('wb') as log:
                process=subprocess.Popen([IP,'netns','exec',NS['service'],TCPDUMP,'--immediate-mode','-U','-i','eth0','-s','0','-c','5000','-w',str(job['path']),'tcp','port','8080'],stdout=subprocess.DEVNULL,stderr=log)
                time.sleep(.35)
                if process.poll() is not None:raise ValueError('Capture could not start.')
                with self.lock:
                    if not job['stop'].is_set():job['public']['status']='collecting'
                deadline=time.monotonic()+job['public']['duration_seconds']
                while time.monotonic()<deadline and not job['stop'].is_set() and process.poll() is None:
                    self.lab.probe()
                    if job['path'].stat().st_size>1048576:break
                    job['stop'].wait(.35)
                if process.poll() is None:process.send_signal(signal.SIGINT)
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            raw=job['path'].read_bytes()
            if job['cancel']:
                with self.lock:job['public'].update(status='cancelled',finished_at_epoch=time.time(),bytes=len(raw))
                return
            if not 24<len(raw)<=1048576:raise ValueError('Capture is empty or exceeded its bound.')
            meta=dict(capture_id=identity,capture_sha256=hashlib.sha256(raw).hexdigest(),generation=self.lab.manifest['generation'],
                recorded_at_epoch=time.time(),scope='Current fixed disconnected lab service health-check capture; known authorised traffic.',
                observation_point=job['public']['observation_point'],capture_duration_seconds=time.time()-job['public']['started_at_epoch'])
            (job['path'].with_suffix('.json')).write_text(json.dumps(meta,indent=2))
            with self.lock:job['public'].update(status='cancelled' if job['cancel'] else 'completed',finished_at_epoch=time.time(),bytes=len(raw),capture=meta)
        except Exception:
            with self.lock:job['public'].update(status='failed',error='Capture failed; no source was imported or action authorised.',finished_at_epoch=time.time())
        finally:
            if process and process.poll() is None:process.kill();process.wait()
            with self.lock:self.active=None
    def get(self,identity,include_capture=False):
        with self.lock:
            if identity not in self.jobs:raise ValueError('Unknown capture session.')
            job=self.jobs[identity];result=dict(job['public'])
            if include_capture:
                if result['status']!='completed':raise ValueError('Only a completed capture may be imported.')
                result['capture']=dict(result['capture'],pcap_base64=base64.b64encode(job['path'].read_bytes()).decode())
            if job['path'].exists():result['bytes']=job['path'].stat().st_size
            return result
    def stop(self,identity,cancel=False):
        with self.lock:
            self.get(identity);job=self.jobs[identity]
            if job['public']['status'] in ('starting','collecting','stopping'):
                job['cancel']=job['cancel'] or cancel;job['public']['status']='stopping';job['stop'].set()
            return self.get(identity)
    def close(self):
        with self.lock:
            thread=self.jobs[self.active]['thread'] if self.active else None
            if self.active:self.stop(self.active,True)
        if thread:thread.join(timeout=5)
