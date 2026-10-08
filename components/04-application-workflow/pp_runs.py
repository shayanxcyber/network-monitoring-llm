"""Durable, source-scoped jobs and ordered public events. One worker per app.

Disconnecting an event reader never repeats or cancels a provider request.
On process restart, unfinished jobs become interrupted rather than being billed
again. Provider reasoning, credentials and arbitrary exception bodies stay out.
"""
from __future__ import annotations

import json
import threading
from pp_workflow import now

TERMINAL = {'complete', 'failed', 'interrupted', 'cancelled'}


class InvestigationCancelled(BaseException):
    """Cooperative control signal, not a model error to retry or correct."""


class InvestigationRuns:
    def __init__(self, store, lock):
        self.store, self.lock = store, lock
        self.stops, self.control = {}, threading.RLock()
        with store.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS investigation_runs (
                    id TEXT PRIMARY KEY, review_id TEXT NOT NULL REFERENCES reviews(id),
                    question TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, turn_id TEXT, error TEXT
                );
                CREATE TABLE IF NOT EXISTS investigation_events (
                    request_id TEXT NOT NULL REFERENCES investigation_runs(id),
                    sequence INTEGER NOT NULL, type TEXT NOT NULL, data TEXT NOT NULL,
                    recorded_at TEXT NOT NULL, PRIMARY KEY(request_id, sequence)
                );
            ''')
            if 'selected_reference' not in {r['name'] for r in db.execute('PRAGMA table_info(investigation_runs)')}:
                db.execute('ALTER TABLE investigation_runs ADD COLUMN selected_reference TEXT')
            abandoned = [r['id'] for r in db.execute("SELECT id FROM investigation_runs WHERE status IN ('queued','running','stopping')")]
            for run_id in abandoned:
                db.execute("UPDATE investigation_runs SET status='interrupted',error=?,updated_at=? WHERE id=?",
                           ('The backend restarted before this investigation completed. It was not sent again.', now(), run_id))
        for run_id in abandoned:
            self.emit(run_id, 'interrupted', {'message': 'Backend restarted. No automatic model retry.'})

    def emit(self, run_id, kind, data):
        if kind not in {'queued', 'started', 'provider_started', 'provider_finished', 'summary',
                        'tool_started', 'tool_finished', 'validation', 'correction', 'stop_requested', 'cancelled', 'complete', 'failed', 'interrupted'}:
            raise ValueError('Unknown public event.')
        with self.store.connect() as db:
            db.execute('INSERT INTO investigation_events SELECT ?, COALESCE(MAX(sequence),0)+1, ?, ?, ? '
                       'FROM investigation_events WHERE request_id=?', (run_id, kind, json.dumps(data), now(), run_id))

    def get(self, review_id, run_id, after=0):
        with self.store.connect() as db:
            row = db.execute('SELECT * FROM investigation_runs WHERE id=? AND review_id=?', (run_id, review_id)).fetchone()
            if not row:
                raise KeyError('Run not found.')
            result = dict(row)
            result['events'] = [dict(e) | {'data': json.loads(e['data'])} for e in db.execute(
                'SELECT sequence,type,data,recorded_at FROM investigation_events WHERE request_id=? AND sequence>? ORDER BY sequence',
                (run_id, after))]
            return result

    def _settle(self, run_id, status, turn_id=None, error=None):
        # Status and terminal event are committed together so an SSE reconnect
        # cannot observe completion without its final event/turn identity.
        with self.store.connect() as db:
            db.execute('UPDATE investigation_runs SET status=?,updated_at=?,turn_id=?,error=? WHERE id=?',
                       (status, now(), turn_id, error, run_id))
            data={'turn_id':turn_id, 'message':error or 'Answer saved and checked.'}
            db.execute('INSERT INTO investigation_events SELECT ?, COALESCE(MAX(sequence),0)+1, ?, ?, ? '
                       'FROM investigation_events WHERE request_id=?', (run_id, status, json.dumps(data), now(), run_id))

    def list(self, review_id):
        with self.store.connect() as db:
            ids = [row['id'] for row in db.execute(
                'SELECT id FROM investigation_runs WHERE review_id=? ORDER BY created_at,id', (review_id,))]
        return [self.get(review_id, run_id) for run_id in ids]

    def cancel(self, review_id, run_id):
        with self.control:
            value = self.get(review_id, run_id)
            if value['status'] in TERMINAL or value['status'] == 'stopping':
                return value
            self.stops.setdefault(run_id, threading.Event()).set()
            with self.store.connect() as db:
                db.execute("UPDATE investigation_runs SET status='stopping',updated_at=? WHERE id=?", (now(), run_id))
            self.emit(run_id, 'stop_requested', {'message': 'Stop requested. Waiting for the current operation to settle; already-sent provider work may still incur cost.'})
            return self.get(review_id, run_id)

    def start(self, review_id, run_id, question, runner, selected_reference=None):
        # Idempotency is checked BEFORE the busy gate, including concurrent reconnects.
        try:
            existing = self.get(review_id, run_id)
        except KeyError:
            existing = None
        if existing:
            if existing['question'] != question or existing.get('selected_reference') != selected_reference:
                raise ValueError('This request ID belongs to a different question or evidence selection.')
            return existing
        if not self.lock.acquire(blocking=False):
            raise ValueError('Another investigation is running. Your draft is unchanged; wait before sending.')
        handed_off = False
        try:
            previous = self.store.begin_request(run_id, review_id)
            if previous and (previous['question'] != question or previous.get('selected_reference') != selected_reference):
                raise ValueError('This request ID belongs to a different question or evidence selection.')
            with self.store.connect() as db:
                db.execute('INSERT INTO investigation_runs (id,review_id,question,status,created_at,updated_at,turn_id,error,selected_reference) VALUES (?,?,?,?,?,?,?,NULL,?)',
                           (run_id, review_id, question, 'complete' if previous else 'queued', now(), now(),
                            previous['run_id'] if previous else None, selected_reference))
            if previous:
                return self.get(review_id, run_id)
            self.emit(run_id, 'queued', {'message': 'Investigation accepted.'})
            self.stops.setdefault(run_id, threading.Event())
            threading.Thread(target=self._work, args=(review_id, run_id, runner),
                             daemon=True, name='packetpilot-investigation').start()
            handed_off = True
            return self.get(review_id, run_id)
        finally:
            if not handed_off:
                self.lock.release()

    def _work(self, review_id, run_id, runner):
        stop = self.stops[run_id]
        def publish(kind, data):
            if stop.is_set():
                raise InvestigationCancelled()
            self.emit(run_id, kind, data)
        publish.cancelled = stop
        try:
            with self.store.connect() as db:
                db.execute("UPDATE investigation_runs SET status='running',updated_at=? WHERE id=? AND status='queued'", (now(), run_id))
            publish('started', {'message': 'Processing this source.'})
            result, _, path = runner(publish)
            with self.control:
                if stop.is_set():
                    raise InvestigationCancelled()
                self.store.finish_request(run_id, review_id, result, path)
                failure = result['explanation'].get('api_error')
                status = 'failed' if failure else 'complete'
                error = failure['message'] if failure else None
                self._settle(run_id, status, result['run_id'], error)
        except InvestigationCancelled:
            self._settle(run_id, 'cancelled', error='Stopped at your request. The attempt is retained; no answer was saved or automatically retried.')
        except Exception:
            message = ('Stopped at your request. The attempt is retained; no answer was saved or automatically retried.' if stop.is_set()
                       else 'Investigation stopped before saving an answer. No automatic model retry was made.')
            self._settle(run_id, 'cancelled' if stop.is_set() else 'failed', error=message)
        finally:
            self.stops.pop(run_id, None)
            self.lock.release()
