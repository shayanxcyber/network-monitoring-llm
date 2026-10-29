"""Root-owned Unix-socket boundary for one fixed isolated lab. No shell API."""
from __future__ import annotations
import json
import os
import pwd
import signal
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path
from pp_linux_lab import LinuxLab
from pp_response_engine import ResponseEngine, ACTIVE, exact
from pp_lab_capture import CaptureSessions

DIRECTORY = Path('/var/lib/packetpilot-response')
SOCKET = Path('/run/packetpilot-response/control.sock')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Install/run through the dedicated root-owned service.')
    os.umask(0o077)
    operator = pwd.getpwnam('capstone')
    lab = LinuxLab(DIRECTORY)
    lab.setup()
    engine = ResponseEngine(lab, DIRECTORY)
    engine.recover()
    captures=CaptureSessions(lab)
    stopped = threading.Event()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            _, uid, _ = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            try:
                if uid not in (0, operator.pw_uid):
                    raise ValueError('This local user is not an authorised lab operator.')
                raw = self.rfile.readline(8193)
                if len(raw) > 8192 or not raw.endswith(b'\n'):
                    raise ValueError('Oversized/incomplete request.')
                def strict_pairs(pairs):
                    obj = {}
                    for key, value in pairs:
                        if key in obj: raise ValueError('Duplicate key.')
                        obj[key] = value
                    return obj
                request = json.loads(raw, object_pairs_hook=strict_pairs)
                exact(request, {'operation', 'data'})
                operation, data = request['operation'], request['data']
                actor = f'local-uid:{uid}'
                with engine.lock:
                    if operation == 'status':
                        exact(data, set()); result = engine.status()
                    elif operation == 'capture':
                        exact(data, set())
                        if captures.active:raise ValueError('A managed capture is already collecting.')
                        if engine.fault or any(a['state'] in ACTIVE for a in engine.actions.values()):
                            raise ValueError('Finish the active action before a new baseline capture.')
                        result = lab.capture()
                    elif operation == 'capture_start':
                        exact(data,{'duration_seconds'})
                        if engine.fault or any(a['state'] in ACTIVE for a in engine.actions.values()):raise ValueError('Finish the active response before collecting a baseline.')
                        result=captures.start(data['duration_seconds'])
                    elif operation in ('capture_status','capture_result','capture_stop','capture_cancel'):
                        exact(data,{'session_id'})
                        result=captures.stop(data['session_id'],operation=='capture_cancel') if operation in ('capture_stop','capture_cancel') else captures.get(data['session_id'],operation=='capture_result')
                    elif operation in ('diagnostic','diagnostic_transfer'):
                        exact(data,set());result=lab.diagnose() if operation=='diagnostic' else lab.diagnose_transfer()
                    elif operation == 'propose':
                        if captures.active:raise ValueError('Finish collection before proposing a response.')
                        result = engine.propose(data, actor)
                    elif operation == 'approve':
                        if captures.active:raise ValueError('Finish collection before approving a response.')
                        result = engine.approve(data, actor)
                    elif operation == 'cancel':
                        exact(data, {'action_id'}); result = engine.cancel(data['action_id'], actor)
                    elif operation == 'rollback':
                        exact(data, {'action_id'}); result = engine.rollback(data['action_id'])
                    else: raise ValueError('Unsupported operation; no general command execution exists.')
                response = {'ok': True, 'result': result}
            except Exception as exc:
                response = {'ok': False, 'error': str(exc)[:400]}
            self.wfile.write((json.dumps(response)+'\n').encode())

    SOCKET.parent.mkdir(mode=0o750, exist_ok=True)
    os.chown(SOCKET.parent, 0, operator.pw_gid)
    os.chmod(SOCKET.parent, 0o750)
    if SOCKET.exists(): SOCKET.unlink()  # Exact service-owned socket, never a caller path.
    server = socketserver.UnixStreamServer(str(SOCKET), Handler)
    os.chown(SOCKET, 0, operator.pw_gid); os.chmod(SOCKET, 0o660)

    def watchdog():
        while not stopped.wait(0.25):
            try: engine.tick()
            except Exception: engine.fault = 'Watchdog error; new responses disabled.'

    threading.Thread(target=watchdog, daemon=True).start()
    def shutdown(_signum, _frame):
        stopped.set()
        captures.close()
        with engine.lock:
            for action in engine.actions.values():
                if action['state'] in ACTIVE: engine.rollback(action['id'], 'service_shutdown')
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try: server.serve_forever(poll_interval=0.25)
    finally:
        stopped.set(); server.server_close()
        if lab.server: lab.server.terminate()


if __name__ == '__main__': main()
