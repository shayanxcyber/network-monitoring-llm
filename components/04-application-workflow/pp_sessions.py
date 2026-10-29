"""Small local SQLite index for reviews; existing per-run evidence is retained."""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from pp_workflow import now


class ReviewStore:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.database = self.directory / "reviews.sqlite3"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS reviews (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, capture TEXT NOT NULL,
                    provider TEXT NOT NULL CHECK(provider IN ('rules','api')),
                    evidence TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS turns (
                    id TEXT PRIMARY KEY, review_id TEXT NOT NULL REFERENCES reviews(id),
                    created_at TEXT NOT NULL, result TEXT NOT NULL, run_path TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, review_id TEXT NOT NULL REFERENCES reviews(id),
                    status TEXT NOT NULL, turn_id TEXT REFERENCES turns(id), created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS previews (
                    id TEXT PRIMARY KEY, review_id TEXT NOT NULL REFERENCES reviews(id),
                    created_at TEXT NOT NULL, result TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS turns_by_review ON turns(review_id, created_at);
                CREATE TABLE IF NOT EXISTS lab_bindings (
                    review_id TEXT PRIMARY KEY REFERENCES reviews(id), binding TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS response_actions (
                    action_id TEXT PRIMARY KEY, review_id TEXT NOT NULL REFERENCES reviews(id)
                );
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,title TEXT NOT NULL,created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_sources (
                    case_id TEXT NOT NULL REFERENCES cases(id),review_id TEXT NOT NULL UNIQUE REFERENCES reviews(id),
                    role TEXT NOT NULL,selected INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY(case_id,review_id)
                );
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, title, capture, provider, evidence):
        review_id, timestamp = str(uuid.uuid4()), now()
        with self.connect() as db:
            db.execute("INSERT INTO reviews VALUES (?,?,?,?,?,?,?)", (
                review_id, title, str(capture), provider, json.dumps(evidence), timestamp, timestamp))
        return self.get(review_id)

    def list(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT r.id,r.title,r.provider,r.created_at,r.updated_at,"
                "(SELECT COUNT(*) FROM turns WHERE turns.review_id=r.id) AS turn_count,"
                "s.case_id,c.title AS case_title,json_extract(r.evidence,'$.capture.sha256') AS sha256,"
                "COALESCE(json_extract(r.evidence,'$.input_kind'),'pcap') AS input_kind "
                "FROM reviews r LEFT JOIN case_sources s ON s.review_id=r.id "
                "LEFT JOIN cases c ON c.id=s.case_id ORDER BY r.updated_at DESC,r.id")]

    def action_sources(self):
        """Read only linked action identities and source metadata, not evidence blobs."""
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                'SELECT a.action_id,r.id AS review_id,r.title AS review_title,r.updated_at '
                'FROM response_actions a JOIN reviews r ON r.id=a.review_id ORDER BY r.updated_at DESC,a.action_id')]

    def case_for(self, review_id):
        with self.connect() as db:
            row=db.execute('SELECT case_id FROM case_sources WHERE review_id=?',(review_id,)).fetchone()
        return self.case(row[0]) if row else None

    def create_case(self, review_id, title):
        if type(title) is not str or not 1<=len(title.strip())<=160: raise ValueError('Use a non-empty case title up to160 characters.')
        self.get(review_id)
        identity=str(uuid.uuid4())
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if self.case_for(review_id): raise ValueError('This source already belongs to a case.')
            db.execute('INSERT INTO cases VALUES (?,?,?)',(identity,title.strip(),now()))
            db.execute('INSERT INTO case_sources VALUES (?,?,?,1)',(identity,review_id,'problem'))
        return self.case(identity)

    def case(self, identity):
        with self.connect() as db:
            row=db.execute('SELECT * FROM cases WHERE id=?',(identity,)).fetchone()
            if not row: raise KeyError('Case not found.')
            result=dict(row)
            result['sources']=[dict(r) for r in db.execute('SELECT c.review_id,c.role,c.selected,r.title,r.evidence FROM case_sources c JOIN reviews r ON r.id=c.review_id WHERE c.case_id=? ORDER BY r.created_at,r.id',(identity,))]
        for source in result['sources']:
            evidence=json.loads(source.pop('evidence'))
            source.update(sha256=evidence['capture']['sha256'],input_kind=evidence.get('input_kind','pcap'))
        return result

    def link_case(self, identity, review_id, role):
        if role not in ('baseline','problem','after','reference'): raise ValueError('Invalid evidence role.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            case=self.case(identity);review=self.get(review_id)
            if len(case['sources'])>=6: raise ValueError('A case supports up to six retained sources.')
            if self.case_for(review_id): raise ValueError('Source already belongs to a case.')
            if review['evidence']['capture']['sha256'] in {s['sha256'] for s in case['sources']}: raise ValueError('The same original evidence is already in this case.')
            db.execute('INSERT INTO case_sources VALUES (?,?,?,1)',(identity,review_id,role))
        return self.case(identity)

    def select_case(self, identity, selected):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            members={r[0] for r in db.execute('SELECT review_id FROM case_sources WHERE case_id=?',(identity,))}
            if not isinstance(selected,list) or not 1<=len(selected)<=6 or len(set(selected))!=len(selected) or not set(selected)<=members: raise ValueError('Choose unique sources in this case.')
            db.execute('UPDATE case_sources SET selected=0 WHERE case_id=?',(identity,))
            for review_id in selected: db.execute('UPDATE case_sources SET selected=1 WHERE case_id=? AND review_id=?',(identity,review_id))
        return self.case(identity)

    def change_case_role(self, identity, review_id, role):
        if role not in ('baseline', 'problem', 'after', 'reference'):
            raise ValueError('Invalid evidence role.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            changed = db.execute('UPDATE case_sources SET role=? WHERE case_id=? AND review_id=?',
                                 (role, identity, review_id))
            if changed.rowcount != 1:
                raise ValueError('That source is not in this case.')
        return self.case(identity)

    def unlink_case(self, identity, review_id):
        """Remove only a current membership; originals and saved answer scopes survive."""
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute('SELECT review_id,selected FROM case_sources WHERE case_id=?', (identity,)).fetchall()
            if review_id not in {r['review_id'] for r in rows}:
                raise ValueError('That source is not in this case.')
            remaining = [r for r in rows if r['review_id'] != review_id]
            if not remaining or not any(r['selected'] for r in remaining):
                raise ValueError('Keep at least one selected source in the case.')
            db.execute('DELETE FROM case_sources WHERE case_id=? AND review_id=?', (identity, review_id))
        return self.case(identity)

    def case_snapshot(self, review_id):
        case=self.case_for(review_id)
        if not case: return None
        selected=[s for s in case['sources'] if s['selected']]
        if review_id not in {s['review_id'] for s in selected}: raise ValueError('Select the current source before asking a case question.')
        case['sources']=[dict(s,evidence=self.get(s['review_id'])['evidence']) for s in selected]
        return case

    def get(self, review_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM reviews WHERE id=?", (review_id,)).fetchone()
            if row is None:
                raise KeyError("Review not found.")
            review = dict(row)
            review["evidence"] = json.loads(review["evidence"])
            review["turns"] = [json.loads(row["result"]) for row in db.execute(
                "SELECT result FROM turns WHERE review_id=? ORDER BY created_at,id", (review_id,))]
            review["previews"] = [dict(row) | {"result": json.loads(row["result"])} for row in db.execute(
                "SELECT id,created_at,result FROM previews WHERE review_id=? ORDER BY created_at,id", (review_id,))]
            binding = db.execute('SELECT binding FROM lab_bindings WHERE review_id=?', (review_id,)).fetchone()
            review['lab_binding'] = json.loads(binding['binding']) if binding else None
            review['response_action_ids'] = [r['action_id'] for r in db.execute(
                'SELECT action_id FROM response_actions WHERE review_id=?', (review_id,))]
            return review

    def bind_lab(self, review_id, binding):
        with self.connect() as db:
            db.execute('INSERT INTO lab_bindings VALUES (?,?)', (review_id, json.dumps(binding)))

    def add_action(self, review_id, action_id):
        with self.connect() as db:
            db.execute('INSERT INTO response_actions VALUES (?,?)', (action_id, review_id))

    def begin_request(self, request_id, review_id):
        with self.connect() as db:
            previous = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            if previous:
                if previous["review_id"] != review_id:
                    raise ValueError("Request belongs to another review.")
                if previous["status"] != "complete":
                    raise ValueError("This request is in progress or was interrupted. It will not be sent twice.")
                return json.loads(db.execute("SELECT result FROM turns WHERE id=?",
                                             (previous["turn_id"],)).fetchone()["result"])
            db.execute("INSERT INTO requests VALUES (?,?,?,NULL,?)",
                       (request_id, review_id, "started", now()))
        return None

    def finish_request(self, request_id, review_id, result, run_path):
        timestamp = now()
        with self.connect() as db:
            db.execute("INSERT INTO turns VALUES (?,?,?,?,?)", (
                result["run_id"], review_id, timestamp, json.dumps(result), str(run_path)))
            db.execute("UPDATE requests SET status='complete',turn_id=? WHERE id=?",
                       (result["run_id"], request_id))
            db.execute("UPDATE reviews SET updated_at=? WHERE id=?", (timestamp, review_id))

    def add_preview(self, review_id, result):
        with self.connect() as db:
            db.execute("INSERT INTO previews VALUES (?,?,?,?)",
                       (str(uuid.uuid4()), review_id, now(), json.dumps(result)))
