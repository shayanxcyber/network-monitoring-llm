"""Loopback-only operator interface, using the existing analysis workflow."""
from __future__ import annotations

import json
import secrets
import threading
import uuid
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from pp_evidence import MAX_BYTES, analyse_capture, preflight
from pp_llm import LLMError, MAX_QUESTION, clean_text
from pp_policy import preview_response
from pp_samples import make_samples
from pp_sessions import ReviewStore
from pp_settings import api_config
from pp_workflow import run_analysis


class NewReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sample: Literal["normal", "port-check"]
    provider: Literal["rules", "api"] = "rules"


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=MAX_QUESTION)
    request_id: uuid.UUID


class Preview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["investigate", "block_source", "no_action"] = "investigate"


def public_review(review):
    return review | {"capture": Path(review["capture"]).name}


def create_app(root, data_dir=None, config_loader=None, client_factory=None, test_mode=False):
    root = Path(root).resolve()
    store = ReviewStore(data_dir or root / "runtime")
    config_loader = config_loader or (lambda: api_config(root))
    if client_factory is None:
        from pp_agent import AgnoClient
        client_factory = lambda config, session: AgnoClient(config, store.directory / "agent-history.sqlite3", session)
    make_samples(root / "sample-data")
    csrf = secrets.token_urlsafe(32)
    request_lock = threading.Lock()
    app = FastAPI(title="PacketPilot", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"] + (["testserver"] if test_mode else []))

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if (request.headers.get("sec-fetch-site") == "cross-site"
                    or (origin and origin != str(request.base_url).rstrip("/"))
                    or not secrets.compare_digest(request.headers.get("x-packetpilot-token", ""), csrf)):
                return JSONResponse({"detail": "Open PacketPilot locally and refresh before submitting."}, status_code=403)
            try:
                size = int(request.headers["content-length"])
                if not 0 <= size <= MAX_BYTES + 65536:
                    raise ValueError
            except (KeyError, ValueError):
                return JSONResponse({"detail": "Request is missing its size or exceeds the 8 MiB upload limit."}, status_code=413)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ValueError)
    async def invalid(_request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(KeyError)
    async def missing(_request, _exc):
        return JSONResponse({"detail": "That saved review was not found."}, status_code=404)

    @app.exception_handler(OSError)
    async def file_error(_request, _exc):
        return JSONResponse({"detail": "A local file could not be accessed. Check the project is available."}, status_code=503)

    def ready():
        try:
            config_loader().endpoint()
            return True
        except (LLMError, ValueError, OSError):
            return False

    def create_review(capture, title, provider):
        if provider == "api" and not ready():
            raise ValueError("Add your API key inside Ubuntu before starting an AI review.")
        evidence = analyse_capture(capture, "auto")
        return public_review(store.create(title, capture, provider, evidence))

    @app.get("/")
    def index():
        return FileResponse(root / "web" / "index.html")

    @app.get("/api/config")
    def configuration():
        config = config_loader()
        return {"application": "PacketPilot", "csrf": csrf, "api_ready": ready(), "model": config.model,
                "thinking": config.thinking, "runtime": "Agno", "actions": "preview_only",
                "history": "All successful turns in the same review; stored in local SQLite.",
                "samples": ["normal", "port-check"], "max_upload_bytes": MAX_BYTES}

    @app.get("/api/reviews")
    def reviews():
        return store.list()

    @app.post("/api/reviews", status_code=201)
    def new_review(body: NewReview):
        return create_review(root / "sample-data" / f"{body.sample}.pcap", f"{body.sample}.pcap", body.provider)

    @app.post("/api/reviews/upload", status_code=201)
    async def upload(file: UploadFile = File(...), provider: Literal["rules", "api"] = Form("rules")):
        data = await file.read(MAX_BYTES + 1)
        await file.close()
        if not data or len(data) > MAX_BYTES:
            raise ValueError("Choose a non-empty classic PCAP no larger than 8 MiB.")
        name = clean_text((file.filename or "capture.pcap").replace("\\", "/").split("/")[-1], 160)
        directory = store.directory / "captures"
        directory.mkdir(exist_ok=True)
        path = directory / f"{uuid.uuid4()}.pcap"
        with path.open("xb") as stream:
            stream.write(data)
        try:
            return await run_in_threadpool(create_review, path, name, provider)
        except Exception:
            path.unlink(missing_ok=True)  # Only this rejected, newly-created upload copy.
            raise

    @app.get("/api/reviews/{review_id}")
    def review(review_id: uuid.UUID):
        return public_review(store.get(str(review_id)))

    @app.post("/api/reviews/{review_id}/questions")
    def ask(review_id: uuid.UUID, body: Question):
        if not request_lock.acquire(blocking=False):
            raise HTTPException(409, "A review is running. Wait for it to finish before asking again.")
        try:
            review = store.get(str(review_id))
            question = clean_text(body.question, MAX_QUESTION)
            path = Path(review["capture"])
            if preflight(path)["sha256"] != review["evidence"]["capture"]["sha256"]:
                raise ValueError("The capture changed. Start a new review so the evidence stays consistent.")
            previous = store.begin_request(str(body.request_id), str(review_id))
            if previous is not None:
                return previous
            client = None
            if review["provider"] == "api":
                try:
                    client = client_factory(config_loader(), str(review_id))
                except LLMError:
                    raise ValueError("The API key/settings are not ready. Add the key inside Ubuntu.") from None
            result, _, run_path = run_analysis(
                path, root / "runs", question, provider=review["provider"],
                client=client, cached_evidence=review["evidence"],
            )
            store.finish_request(str(body.request_id), str(review_id), result, run_path)
            return result
        finally:
            request_lock.release()

    @app.post("/api/reviews/{review_id}/preview")
    def preview(review_id: uuid.UUID, body: Preview):
        review = store.get(str(review_id))
        evidence = review["evidence"]
        target = evidence["candidate_source"] if body.action == "block_source" else None
        result = preview_response(evidence, body.action, target, 60, False)
        store.add_preview(str(review_id), result)
        return result

    @app.get("/api/reviews/{review_id}/export")
    def export(review_id: uuid.UUID):
        return JSONResponse(public_review(store.get(str(review_id))), headers={
            "Content-Disposition": f'attachment; filename="PacketPilot-review-{review_id}.json"',
        })

    app.mount("/assets", StaticFiles(directory=root / "web"), name="assets")
    return app
