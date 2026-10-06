"""Typed temporary lab response lifecycle; no model authority or shell text."""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from pp_response_operations import catalogue, command_plan, validate_parameters

TARGET = "10.77.0.20"
DESTINATION = "10.77.0.10"
PORT = 8080
ACTIVE = {"applying", "active", "rollback_failed"}


def stamp():
    return datetime.now(timezone.utc).isoformat()


def exact(data, fields):
    if type(data) is not dict or set(data) != set(fields):
        raise ValueError("Unexpected request fields.")


class ResponseEngine:
    def __init__(self, lab, directory, clock=time.time, monotonic=time.monotonic):
        self.lab, self.directory, self.clock = lab, Path(directory), clock
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "actions.json"
        self.lock = threading.RLock()
        self.actions = json.loads(self.path.read_text()) if self.path.exists() else {}
        self.fault = None
        self.monotonic, self.deadlines = monotonic, {}
        self.rollback_retry_after = {}

    def save(self):
        temporary = self.path.with_suffix('.new')
        with temporary.open('w', encoding='utf-8') as stream:
            json.dump(self.actions, stream, indent=2)
            stream.flush()
            import os
            os.fsync(stream.fileno())
        temporary.replace(self.path)

    def event(self, action, kind, **data):
        event = dict(at=stamp(), event=kind, **data)
        action['events'].append(event)
        self.save()
        with (self.directory / 'audit.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(dict(action_id=action['id'], **event))+'\n')

    @staticmethod
    def public(action):
        return {k: v for k, v in action.items() if k != 'approval_hash'}

    def get(self, action_id):
        if action_id not in self.actions:
            raise ValueError('Unknown response action.')
        return self.public(self.actions[action_id])

    def status(self):
        with self.lock:
            return {'lab': self.lab.status(), 'fault': self.fault,
                    'actions': [self.public(a) for a in self.actions.values()], 'capabilities': catalogue()}

    def recover(self):
        """A broker restart revokes approvals and rolls back known active rules."""
        with self.lock:
            for action in self.actions.values():
                if action['state'] in ACTIVE:
                    self.rollback(action['id'], 'restart_recovery')
                elif action['state'] == 'proposed':
                    action['state'] = 'approval_expired'
                    self.event(action, 'approval_revoked_on_restart')

    def propose(self, data, actor):
        legacy = {'capture_id', 'capture_sha256', 'target', 'duration_seconds', 'reason'}
        modern = legacy | {'operation', 'destination', 'port', 'rate_kbit', 'origin'}
        if type(data) is not dict or set(data) not in (legacy, modern):
            raise ValueError('Unexpected request fields.')
        duration = data['duration_seconds']
        parameters = validate_parameters(data.get('operation', 'block_source'), data['target'],
                                         data.get('destination', DESTINATION), data.get('port', PORT),
                                         duration, data.get('rate_kbit'))
        origin = data.get('origin')
        if origin is not None:
            exact(origin, {'review_id', 'turn_id', 'recommendation_index', 'references'})
            for key in ('review_id', 'turn_id'):
                if str(uuid.UUID(origin[key])) != origin[key]: raise ValueError('Invalid proposal origin.')
            if type(origin['recommendation_index']) is not int or not 0 <= origin['recommendation_index'] <= 7:
                raise ValueError('Invalid recommendation index.')
            if (type(origin['references']) is not list or not 1 <= len(origin['references']) <= 16
                    or any(type(r) is not str or len(r) > 100 for r in origin['references'])):
                raise ValueError('Invalid recommendation references.')
        if type(data['reason']) is not str or not 1 <= len(data['reason'].strip()) <= 1400:
            raise ValueError('A concise operator reason is required.')
        with self.lock:
            if self.fault or any(a['state'] in ACTIVE for a in self.actions.values()):
                raise ValueError('Resolve the active action or safety fault first.')
            if origin and any(a['state'] == 'proposed' and a.get('origin') == origin for a in self.actions.values()):
                raise ValueError('This recommendation already has a pending proposal; cancel or finish it first.')
            binding = self.lab.validate_capture(data['capture_id'], data['capture_sha256'])
            health = self.lab.probe()
            if not health['source_reachable'] or not health['control_reachable']:
                raise ValueError('Both lab clients must reach the service before a proposal.')
            token = secrets.token_urlsafe(32)
            action_id = str(uuid.uuid4())
            operation = parameters['operation']
            phrase = (f'BLOCK {TARGET} TO {DESTINATION}:{PORT} FOR {duration}s' if operation == 'block_source' else
                      f'LIMIT {TARGET} FROM {DESTINATION}:{PORT} TO {parameters["rate_kbit"]}kbit FOR {duration}s')
            measured = self.lab.measure() if operation == 'rate_limit_service' else None
            if measured and measured['source']['kbit_per_second'] < parameters['rate_kbit']*3:
                raise ValueError('The measured baseline is too slow for a meaningful rate-limit demonstration.')
            action = dict(id=action_id, state='proposed', actor=actor, created_at=stamp(),
                          capture_id=data['capture_id'], capture_sha256=data['capture_sha256'],
                          generation=binding['generation'], target=TARGET, destination=DESTINATION,
                          protocol='tcp', port=PORT, duration_seconds=duration, reason=data['reason'].strip(),
                          approval_deadline=self.clock()+60, confirmation=phrase,
                          approval_hash=hashlib.sha256(token.encode()).hexdigest(), events=[])
            action.update(operation=operation, parameters=parameters, origin=origin,
                          command_plan=command_plan(parameters, action_id), baseline_measurement=measured)
            self.actions[action_id] = action
            self.event(action, 'proposal_created', precheck=health,
                       scope='Isolated lab service only; no current change.')
            return self.public(action) | {'approval_token': token}

    def cancel(self, action_id, actor):
        with self.lock:
            if action_id not in self.actions: raise ValueError('Unknown response action.')
            action = self.actions[action_id]
            if actor != action['actor']: raise ValueError('Proposal belongs to another operator.')
            if action['state'] != 'proposed': raise ValueError('This proposal is not pending.')
            action['state'] = 'cancelled'
            self.event(action, 'operator_cancelled', network_changed=False)
            return self.public(action)

    def approve(self, data, actor):
        exact(data, {'action_id', 'approval_token', 'confirmation'})
        with self.lock:
            if type(data['action_id']) is not str or data['action_id'] not in self.actions:
                raise ValueError('Unknown response action.')
            action = self.actions[data['action_id']]
            if action['state'] != 'proposed':
                raise ValueError('Approval is one-time; this proposal is no longer pending.')
            if self.clock() > action['approval_deadline']:
                action['state'] = 'approval_expired'
                self.event(action, 'approval_expired')
                raise ValueError('Proposal expired. Inspect current evidence and prepare another.')
            if actor != action['actor'] or type(data['approval_token']) is not str or not secrets.compare_digest(
                    hashlib.sha256(data['approval_token'].encode()).hexdigest(), action['approval_hash']):
                raise ValueError('Approval does not match the proposal and operator.')
            if data['confirmation'] != action['confirmation']:
                raise ValueError('Explicit confirmation must exactly match the displayed scope.')
            if self.fault or any(a['state'] in ACTIVE for a in self.actions.values()):
                raise ValueError('Another response or safety fault is active.')
            binding = self.lab.validate_capture(action['capture_id'], action['capture_sha256'])
            if binding['generation'] != action['generation']:
                raise ValueError('Lab identity changed. Create a fresh review.')
            health = self.lab.probe()
            if not all(health[k] for k in ('source_reachable', 'control_reachable')):
                raise ValueError('The lab baseline changed. No rule was applied.')
            operation = action.get('operation', 'block_source')
            measured = self.lab.measure() if operation == 'rate_limit_service' else None
            if measured and measured['source']['kbit_per_second'] < action['parameters']['rate_kbit']*3:
                raise ValueError('Rate baseline changed. No shaping was applied.')
            action['state'] = 'applying'
            action['approved_at'] = stamp()
            action['expires_at_epoch'] = self.clock()+action['duration_seconds']
            self.deadlines[action['id']] = self.monotonic()+action['duration_seconds']
            self.event(action, 'explicit_operator_approval', actor=actor, baseline=health, measurement=measured)
            try:
                applied = (self.lab.block(action['id']) if operation == 'block_source'
                           else self.lab.rate_limit(action['id'], action['parameters']))
                self.event(action, 'rule_applied', evidence=applied)
                checked = self.lab.probe()
                if operation == 'block_source':
                    checked['rule'] = self.lab.rule(action['id'])
                    if checked['source_reachable'] or not checked['control_reachable'] or not checked['rule']['present']:
                        raise RuntimeError('Block effect or unaffected-control check failed.')
                else:
                    checked['rule'] = self.lab.rate_state(action['id'])
                    checked['measurement'] = self.lab.measure()
                    source, control = checked['measurement']['source'], checked['measurement']['control']
                    rate = action['parameters']['rate_kbit']
                    checked['criteria'] = dict(source_slower=source['kbit_per_second'] < measured['source']['kbit_per_second']*.4,
                                               within_bounded_rate=source['kbit_per_second'] <= rate*1.8,
                                               control_unaffected=control['seconds'] <= max(.02, measured['control']['seconds']*4),
                                               control_time_tolerance_seconds=max(.02, measured['control']['seconds']*4))
                    if (not checked['rule']['present'] or not all(checked['criteria'].values())
                            or not all(checked[k] for k in ('source_reachable', 'control_reachable'))):
                        raise RuntimeError('Measured rate-limit effect or unaffected-control check failed.')
                action['state'] = 'active'
                self.event(action, 'effect_verified', evidence=checked)
            except Exception as exc:
                try:
                    self.event(action, 'execution_or_verification_failed', error=str(exc)[:300])
                finally:
                    self.rollback(action['id'], 'verification_failure')
            return self.public(action)

    def rollback(self, action_id, reason='operator_rollback'):
        with self.lock:
            if action_id not in self.actions:
                raise ValueError('Unknown response action.')
            action = self.actions[action_id]
            if action['state'] not in ACTIVE:
                return self.public(action)
            try:
                operation = action.get('operation', 'block_source')
                if operation == 'block_source': self.lab.unblock(action_id)
                else: self.lab.unrate(action_id)
                checked = self.lab.probe()
                checked['rule'] = (self.lab.rule(action_id) if operation == 'block_source' else self.lab.rate_state(action_id))
                if checked['rule']['present'] or not all(checked[k] for k in ('source_reachable', 'control_reachable')):
                    raise RuntimeError('Rollback did not restore both clients and remove the rule.')
                if operation == 'rate_limit_service':
                    checked['measurement'] = self.lab.measure()
                    baseline = action['baseline_measurement']
                    if any(checked['measurement'][r]['seconds'] > max(.2, baseline[r]['seconds']*4) for r in ('source', 'control')):
                        raise RuntimeError('Shaper removed but measured transfer performance is not restored.')
                action['state'] = 'expired' if reason == 'automatic_expiry' else 'rolled_back'
                self.rollback_retry_after.pop(action_id, None)
                self.fault = None
                self.event(action, reason, restored=True, evidence=checked)
            except Exception as exc:
                action['state'] = 'rollback_failed'
                self.fault = 'Rollback needs attention; new responses disabled.'
                self.rollback_retry_after[action_id] = self.monotonic()+2
                self.event(action, 'rollback_failed', reason=reason, error=str(exc)[:300])
            return self.public(action)

    def tick(self):
        with self.lock:
            for action in self.actions.values():
                if action['state'] == 'proposed' and self.clock() > action['approval_deadline']:
                    action['state'] = 'approval_expired'
                    self.event(action, 'approval_expired')
                elif action['state'] in ACTIVE and self.monotonic() >= self.rollback_retry_after.get(action['id'], float('-inf')) and (action['state'] == 'rollback_failed'
                        or self.clock() >= action['expires_at_epoch']
                        or self.monotonic() >= self.deadlines.get(action['id'], float('inf'))):
                    self.rollback(action['id'], 'automatic_expiry')
