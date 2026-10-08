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
                "SELECT id,title,provider,created_at,updated_at,"
                "(SELECT COUNT(*) FROM turns WHERE turns.review_id=reviews.id) AS turn_count "
                "FROM reviews ORDER BY updated_at DESC,id")]

    def action_sources(self):
        """Read only linked action identities and source metadata, not evidence blobs."""
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                'SELECT a.action_id,r.id AS review_id,r.title AS review_title,r.updated_at '
                'FROM response_actions a JOIN reviews r ON r.id=a.review_id ORDER BY r.updated_at DESC,a.action_id')]

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
