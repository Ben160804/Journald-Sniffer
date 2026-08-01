from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import sys, os as _os
sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "fac10sniffer"))

from connection import connectdb, closedbconn
from emitter import persist_auth_event
from llm import classify_with_llm
from parser import parse_rawlog
from watchdogv2 import watchdog

app = FastAPI(
    title="Journald-Sniffer API",
    description="Linux auth event ingestion and threat detection pipeline",
    version="1.0.0",
)

# --- Schemas ---

class HealthResponse(BaseModel):
    status: str
    db: str
    groq: str

class IngestResponse(BaseModel):
    status: str
    inserted: int
    detail: Optional[str] = None

class ParseResponse(BaseModel):
    status: str
    sessions_processed: int
    llm_calls: int

class AlertResponse(BaseModel):
    brute_force: List[dict]
    scan: List[dict]
    success_after_failure: List[dict]

class SessionQuery(BaseModel):
    src_ip: Optional[str] = None
    outcome: Optional[str] = None
    limit: int = 50

class RawQuery(BaseModel):
    program: Optional[str] = None
    limit: int = 50

# --- Endpoints ---

@app.get("/health", response_model=HealthResponse)
def health():
    db_status = "ok"
    groq_status = "ok"
    try:
        conn = connectdb()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        closedbconn()
    except Exception:
        db_status = "error"
    return {"status": "ok", "db": db_status, "groq": groq_status}

@app.post("/ingest", response_model=IngestResponse)
def ingest():
    """Trigger journal ingestion into raw_logs. Requires systemd (Linux host only)."""
    try:
        from systemd import journal
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="python-systemd not available. /ingest requires a Linux host with systemd."
        )
    from ingestor import read
    try:
        conn = connectdb()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM raw_logs")
        before = cur.fetchone()[0]
        cur.close()
        closedbconn()
        read()
        conn = connectdb()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM raw_logs")
        after = cur.fetchone()[0]
        cur.close()
        closedbconn()
        inserted = after - before
        return {"status": "ok", "inserted": inserted}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/parse", response_model=ParseResponse)
def parse():
    """Parse raw_logs into auth_logs using the existing parser."""
    try:
        llm_calls = 0
        # Monkey-patch llm to count calls
        original_llm = classify_with_llm
        def counting_llm(buf):
            nonlocal llm_calls
            llm_calls += 1
            return original_llm(buf)
        import parser as parser_mod
        parser_mod.classify_with_llm = counting_llm
        parse_rawlog()
        return {"status": "ok", "sessions_processed": llm_calls, "llm_calls": llm_calls}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/alerts", response_model=AlertResponse)
def alerts():
    """Run watchdog threat detection and return alerts as JSON."""
    try:
        result = watchdog()
        # watchdog prints to stdout, re-run queries here to capture structured data
        conn = connectdb()
        cur = conn.cursor()
        brute = []
        cur.execute("""
            SELECT src_ip, SUM(failure_count), COUNT(*), MIN(start_time), MAX(end_time)
            FROM auth_logs
            WHERE src_ip IS NOT NULL
            AND start_time > now() - interval '10 minutes'
            GROUP BY src_ip
            HAVING SUM(failure_count) >= 5
        """)
        for r in cur.fetchall():
            brute.append({"src_ip": r[0], "failures": r[1], "sessions": r[2], "window": f"{r[3]}->{r[4]}"})
        scan = []
        cur.execute("""
            SELECT src_ip, SUM(neutral_count), COUNT(*)
            FROM auth_logs
            WHERE src_ip IS NOT NULL
            AND start_time > now() - interval '10 minutes'
            GROUP BY src_ip
            HAVING SUM(neutral_count) >= 12
            AND SUM(success_count) = 0
        """)
        for r in cur.fetchall():
            scan.append({"src_ip": r[0], "neutrals": r[1], "sessions": r[2]})
        saf = []
        cur.execute("""
            SELECT src_ip, username, SUM(failure_count), SUM(success_count), MIN(start_time)
            FROM auth_logs
            WHERE src_ip IS NOT NULL
            AND start_time > now() - interval '10 minutes'
            GROUP BY src_ip, username
            HAVING SUM(failure_count) > 0
            AND SUM(success_count) > 0
        """)
        for r in cur.fetchall():
            saf.append({"src_ip": r[0], "user": r[1], "failures": r[2], "success": r[3], "time": str(r[4])})
        cur.close()
        closedbconn()
        return {"brute_force": brute, "scan": scan, "success_after_failure": saf}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sessions")
def sessions(src_ip: Optional[str] = None, outcome: Optional[str] = None, limit: int = 50):
    """Query auth_logs with optional filters."""
    try:
        conn = connectdb()
        cur = conn.cursor()
        q = "SELECT id, event_time, program, pid, outcome, username, src_ip, hostname, failure_count, success_count, neutral_count FROM auth_logs WHERE 1=1"
        params = []
        if src_ip:
            q += " AND src_ip = %s"
            params.append(src_ip)
        if outcome:
            q += " AND outcome = %s"
            params.append(outcome)
        q += " ORDER BY event_time DESC LIMIT %s"
        params.append(limit)
        cur.execute(q, params)
        rows = cur.fetchall()
        cur.close()
        closedbconn()
        keys = ["id", "event_time", "program", "pid", "outcome", "username", "src_ip", "hostname", "failure_count", "success_count", "neutral_count"]
        return [dict(zip(keys, r)) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/raw")
def raw_logs(program: Optional[str] = None, limit: int = 50):
    """Query raw_logs with optional program filter."""
    try:
        conn = connectdb()
        cur = conn.cursor()
        q = "SELECT id, program, hostname, ingestion_time, event_time, pid, log_source FROM raw_logs WHERE 1=1"
        params = []
        if program:
            q += " AND program = %s"
            params.append(program)
        q += " ORDER BY id DESC LIMIT %s"
        params.append(limit)
        cur.execute(q, params)
        rows = cur.fetchall()
        cur.close()
        closedbconn()
        keys = ["id", "program", "hostname", "ingestion_time", "event_time", "pid", "log_source"]
        return [dict(zip(keys, r)) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
