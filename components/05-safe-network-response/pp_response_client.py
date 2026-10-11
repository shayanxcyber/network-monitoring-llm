"""Unprivileged fixed-protocol client; no SSH/sudo/API credentials."""
import json
import os
import socket


class ResponseClient:
    def call(self, operation, data=None):
        if os.name == 'nt':
            raise ValueError('Linux lab response is unavailable on this Windows-only backend. Open the Ubuntu backend through its SSH tunnel.')
        raw = (json.dumps({'operation': operation, 'data': data or {}})+'\n').encode()
        if len(raw) > 8192: raise ValueError('Response request is too large.')
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(30)
                client.connect('/run/packetpilot-response/control.sock')
                client.sendall(raw)
                with client.makefile('rb') as stream: response = stream.readline(2_000_001)
            if len(response) > 2_000_000: raise ValueError('Lab response exceeds its limit.')
            result = json.loads(response)
        except (OSError, json.JSONDecodeError):
            raise ValueError('The isolated Linux response service is unavailable. No new action was approved.') from None
        if not result['ok']: raise ValueError(result['error'])
        return result['result']
