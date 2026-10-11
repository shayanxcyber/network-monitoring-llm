"""Explicit administrator installation of the fixed broker, never called by the model."""
import json
import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
DEST = Path('/usr/local/lib/packetpilot-response')
FILES = ('pp_response_engine.py','pp_linux_lab.py','pp_response_broker.py','pp_response_operations.py')


def command(argv):
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=30).stdout


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ['--install']:
        raise SystemExit('Usage: sudo python3 install_response_service.py --install')
    pwd.getpwnam('capstone')
    for binary in ('/usr/sbin/ip','/usr/sbin/iptables','/usr/sbin/tc','/usr/bin/tcpdump','/usr/bin/python3'):
        if not Path(binary).is_file(): raise SystemExit('Required binary missing: '+binary)
    if DEST.is_symlink(): raise SystemExit('Refusing a symlink installation destination.')
    DEST.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chown(DEST,0,0); os.chmod(DEST,0o755)
    # Stop the old known service first so it can roll back its own active rule.
    subprocess.run(['systemctl','stop','packetpilot-response.service'],capture_output=True,timeout=20)
    for filename in FILES:
        target=DEST/filename
        if target.is_symlink(): raise SystemExit('Refusing a symlink code target.')
        shutil.copyfile(SOURCE/filename,target);os.chown(target,0,0);os.chmod(target,0o644)
    data=Path('/var/lib/packetpilot-response')
    if data.is_symlink(): raise SystemExit('Refusing a symlink data directory.')
    data.mkdir(mode=0o700,exist_ok=True);os.chown(data,0,0);os.chmod(data,0o700)
    unit=Path('/etc/systemd/system/packetpilot-response.service')
    if unit.is_symlink(): raise SystemExit('Refusing a symlink unit target.')
    shutil.copyfile(SOURCE/'packetpilot-response.service',unit);os.chown(unit,0,0);os.chmod(unit,0o644)
    command(['systemctl','daemon-reload'])
    command(['systemctl','enable','--now','packetpilot-response.service'])
    print(json.dumps({'service':command(['systemctl','is-active','packetpilot-response.service']).strip(),
                      'root_owned_code':str(DEST),'operator':'capstone','scope':'Disconnected lab only'}))


if __name__=='__main__':main()
