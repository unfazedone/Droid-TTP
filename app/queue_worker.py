"""Durable, network-isolated analysis queue consumer."""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent
for key in ("DROIDTTP_DATA_DIR", "DROIDTTP_ANALYSIS_TIMEOUT_SECONDS"):
    if not os.getenv(key):
        configured = dotenv_values(ROOT / ".env").get(key)
        if configured:
            os.environ[key] = configured

os.environ["DROIDTTP_PROCESS_ROLE"] = "worker"

from app.main import connect, initialize, process_analysis, purge_expired_samples, recover_interrupted_analysis


async def run() -> None:
    initialize()
    recover_interrupted_analysis()
    next_retention_sweep = 0.0
    while True:
        if time.monotonic() >= next_retention_sweep:
            try:
                purge_expired_samples()
            except Exception as exc:
                print(f"Retention sweep failed: {type(exc).__name__}", flush=True)
            next_retention_sweep = time.monotonic() + 3600

        with connect() as con:
            row = con.execute(
                "SELECT id FROM samples WHERE analysis_status='queued' ORDER BY uploaded_at,id LIMIT 1"
            ).fetchone()
        if row:
            try:
                await process_analysis(row["id"])
            except Exception as exc:
                print(f"Analysis job failed ({row['id']}): {type(exc).__name__}", flush=True)
                with connect() as con:
                    con.execute(
                        "UPDATE samples SET analysis_status='failed',analysis_progress=100,analysis_completed_at=?,analysis_error='Analysis worker failed unexpectedly.' WHERE id=?",
                        (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), row["id"]),
                    )
            continue
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(run())
