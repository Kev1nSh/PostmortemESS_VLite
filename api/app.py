import asyncio
import time

from typing import Literal

from fastapi import FastAPI, UploadFile, File 
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from src.metrics import (
    ANALYSIS_REQUESTS,
    ANALYSIS_TOTAL,
    ANALYSIS_ERRORS_TOTAL,
    ANALYSIS_DURATION_SECONDS
)

from src.api_service import analyze_email_bytes
from src import db

app = FastAPI(title="PostmortemESS API")

Period = Literal["24h", "7d", "30d", "90d", "all"]

PURGE_INTERVAL = 24 * 60 * 60  #  Cleanup runs every 24 hours

@app.get("/")
def root():
    return {

            "application": "PostmortemESS",
            "description": "Email Security Service",
            "status": "online",
            "documentation": "/docs"
        }

async def _purge_loop():
    while True:
        # This loop runs in the background and purges expired data from db.
        await run_in_threadpool(db.purge_expired_data)
        await asyncio.sleep(PURGE_INTERVAL)  # Wait for the next purge cycle


@app.on_event("startup")
def startup():
    db.init_db()
    app.state.purge_task = asyncio.create_task(_purge_loop())   # Start the purge loop in the background when starting.

@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    ANALYSIS_REQUESTS.inc()
    start_time = time.perf_counter()

    try:
        raw_bytes = await file.read()

        result = await run_in_threadpool(
            analyze_email_bytes, raw_bytes, file.filename
        )

        ANALYSIS_TOTAL.inc()

        sender_address = result["headers"].get("from", "")
        sender_domain = result["domain"]
        report_id = result["report_id"]

        db.save_report(
            report_id,
            result["verdict"],
            sender_address,
            sender_domain,
            result
        )

        db.record_domain_report(sender_domain)
        db.record_sender_address(
            sender_address,
            result["verdict"]
        )

        return result

    except Exception:
        ANALYSIS_ERRORS_TOTAL.inc()
        raise

    finally:
        ANALYSIS_DURATION_SECONDS.observe(
            time.perf_counter() - start_time
        )

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/reports")
def get_report(limit: int = 50):
    return db.get_reports(limit)

@app.get("/stats/domains")
def get_domain_stats(period: Period = "90d"):
    return db.get_domain_stats(period)

@app.get("/stats/verdicts")
def get_verdict_stats(period: Period = "30d"):
    return db.get_verdict_stats(period)

@app.get("/stats/analyses")
def get_analysis_stats(period: Period = "30d"):
    return db.get_analysis_stats(period)