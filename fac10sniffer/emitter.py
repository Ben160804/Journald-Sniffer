from connection import connectdb, closedbconn

def persist_auth_event(cur,buf, outcome):

    cur.execute(
    """
    INSERT INTO auth_logs (
        event_time,
        program,
        pid,
        action,
        outcome,
        username,
        uid,
        src_ip,
        hostname,
        start_time,
        end_time,
        failure_count,
        success_count,
        neutral_count,
        derived_from_raw_id,
        jcursor
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """,
    (
        buf.first_time, 
        buf.program,
        buf.pid,
        "auth_session",
        outcome,
        buf.username,
        buf.uid,
        buf.src_ip,
        buf.hostname,
        buf.first_time,
        buf.last_time,
        buf.failure_count,
        buf.success_count,
        buf.neutral_count,
        buf.raw_ids,
        buf.jcursors,
    )
)
 
    cur.execute(
    "UPDATE ingest_state SET last_jcursor = %s WHERE id = true;",
    (buf.jcursors[-1],)
)
 

   


