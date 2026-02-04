from connection import connectdb, closedbconn
#import ast
from datetime import timedelta
from emitter import persist_auth_event
import re

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b') #gpt hooked me up
VALID_OUTCOMES = {"success", "failure", "neutral"}
AUTH_PROGS = {"sudo", "su", "sshd-session"}
WINDOW_SECONDS = 60
FAILURE_THRESHOLD = 3
NEUTRAL_THRESHOLD = 8


class raw_fact:
    __slots__ = (
        "raw_id",
        "jcursor",
        "time",
        "program",
        "pid",
        "uid",
        "username",
        "src_ip",
        "host_name",
        "message",
        "outcome_label",
        "flags",
    )

    def __init__(
        self,
        raw_id,
        jcursor,
        time,
        program,
        pid,
        uid,
        username,
        src_ip,
        host_name,
        message,
        outcome_label,
        flags=None,
    ):
        if outcome_label not in VALID_OUTCOMES:
            raise ValueError("invalid outcome_label")

        self.raw_id = raw_id
        self.jcursor = jcursor
        self.time = time
        self.program = program
        self.pid = pid
        self.uid = uid
        self.username = username
        self.src_ip = src_ip
        self.host_name = host_name
        self.message = message
        self.outcome_label = outcome_label
        self.flags = flags if flags is not None else set()


class AuthBuffer:
    __slots__ = (
        "program",
        "pid",
        "raw_ids",
        "jcursors",
        "first_time",
        "last_time",
        "uid",
        "username",
        "src_ip",
        "flags",
        "failure_count",
        "success_count",
        "neutral_count",
        "hostname"
    )

    def __init__(self, fact):
        self.program = fact.program
        self.pid = fact.pid

        self.raw_ids = [fact.raw_id]
        self.jcursors = [fact.jcursor]

        self.first_time = fact.time
        self.last_time = fact.time

        self.uid = fact.uid
        self.username = fact.username
        self.src_ip = fact.src_ip

        self.flags = set(fact.flags)

        self.failure_count = 0
        self.success_count = 0
        self.neutral_count = 0
        self.hostname = fact.host_name

        self._ingest(fact)

    def _ingest(self, fact):
        if fact.outcome_label == "failure":
            self.failure_count += 1
        elif fact.outcome_label == "success":
            self.success_count += 1
        else:
            self.neutral_count += 1

    def append(self, fact):
        self.raw_ids.append(fact.raw_id)
        self.jcursors.append(fact.jcursor)

        if fact.time > self.last_time:
            self.last_time = fact.time

        if self.uid is None and fact.uid is not None:
            self.uid = fact.uid

        if self.username is None and fact.username is not None:
            self.username = fact.username

        if self.src_ip is None and fact.src_ip is not None:
            self.src_ip = fact.src_ip

        if self.hostname is None and fact.host_name is not None:
            self.hostname = fact.host_name

        self.flags |= fact.flags
        self._ingest(fact)

def extract_src_ip(program, payload, message):
    if program not in {"sshd", "sshd-session"}:
        return None

    for key in ("REMOTE_ADDR", "SSH_CONNECTION", "ADDR"):
        val = payload.get(key)
        if val:
            m = IP_RE.search(val)
            if m:
                return m.group(0)

    if message:
        m = IP_RE.search(message)
        if m:
            return m.group(0)

    return None

def is_auth_failure(msg):
    if not msg:
        return False

    msg = msg.lower()
    
    return(
     "authentication failure" in msg or
        "authentication failed" in msg or
        "incorrect password" in msg or
        "sorry, try again" in msg or
        "not in sudoers" in msg or
        "account locked" in msg or
        "permission denied" in msg or
        "failed password" in msg or
        "invalid user" in msg or
        "pam authentication failure" in msg or
        "authentication failures" in msg or
        "more authentication failures" in msg) 


def is_auth_success(msg):
    if not msg:
        return False

    msg = msg.lower()

    return (
        "authentication success" in msg or
        "accepted password" in msg or
        "session opened" in msg
    )



def classify(program, message):
    if program not in AUTH_PROGS:
        return "neutral", set()

    if is_auth_failure(message):
        return "failure", {"AUTH_FAILURE"}

    if is_auth_success(message):
        return "success", {"AUTH_SUCCESS"}

    return "neutral", {"AUTH_EVENT"}



def flush_buffer(cur, buf):
    print("FLUSHING:", buf.program, buf.pid, buf.failure_count, buf.neutral_count, buf.success_count)

    if buf.success_count > 0 and buf.failure_count == 0:
        outcome = "success"

    elif buf.program in ("sshd", "sshd-session") and buf.success_count == 0:
        outcome = "failure"

    elif buf.failure_count >= FAILURE_THRESHOLD:
        outcome = "failure"

    elif buf.neutral_count >= NEUTRAL_THRESHOLD:
        outcome = "suspicious"

    else:
        outcome = "unknown"

    persist_auth_event(cur, buf, outcome)







def parse_rawlog():
    conn = connectdb()
    cursor = conn.cursor()
    
    cursor.execute(
    "SELECT last_jcursor FROM ingest_state WHERE id = true;"
    )
    last_jcursor = cursor.fetchone()[0]

    if last_jcursor:
        cursor.execute(
        """
        SELECT * FROM raw_logs
        WHERE journal_cursor > %s
        ORDER BY journal_cursor ASC
        """,
        (last_jcursor,)
        )
    else:
        cursor.execute(
        """
        SELECT * FROM raw_logs
        ORDER BY journal_cursor ASC
        """
        )
    raw_logs = cursor.fetchall()
    buffers = {}
    for i in raw_logs:
        raw_id = i[0]
        program = i[1]
        host_name = i[2]
        event_time = i[4]
        pid = i[5]
        payload = i[6]
        journal_cursor = i[8]
        uid = payload.get("_UID")
        message = payload.get("MESSAGE")
        src_ip = extract_src_ip(program, payload, message)
        username = None
        

        outcome_label, flags = classify(program, message)

        fact = raw_fact(
            raw_id=raw_id,
            jcursor=journal_cursor,
            time=event_time,
            program=program,
            pid=pid,
            uid=uid,
            username=username,
            src_ip=src_ip,
            host_name=host_name,
            message=message,
            outcome_label=outcome_label,
            flags=flags,
        )

   
        key = (fact.program, fact.pid)

        if key not in buffers:
            buffers[key] = AuthBuffer(fact)
            continue

        buf = buffers[key]

        if fact.time > buf.first_time + timedelta(seconds=WINDOW_SECONDS):
            flush_buffer(cursor,buf)
            buffers[key] = AuthBuffer(fact)
        else:
            buf.append(fact)

    

    for buf in buffers.values():
        flush_buffer(cursor,buf)
    conn.commit() 
    cursor.close()
    closedbconn()








parse_rawlog()



