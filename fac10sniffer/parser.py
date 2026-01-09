from connection import connectdb, closedbconn
import ast


def parse_rawlog():
    conn = connectdb()
    cursor = conn.cursor()
    cursor.execute('''
    select * from auth_logs
    ''')
    auth_entry = cursor.fetchone()
    if auth_entry is None:
        cursor.execute('''
        select max(journal_cursor) from raw_logs
                       ''')
        max_jcursor_rlogs = cursor.fetchone()

        # id,pid,program,hostname,outcome,event time
        # raw_log_id,jcursor(same as raw_log)
        cursor.execute('''
        select id,program,hostname,ingestion_time,pid,raw_msg,
        log_source,journal_cursor from raw_logs where journal_cursor <= %s order by journal_cursor
        ''', max_jcursor_rlogs)
        raw_logs = cursor.fetchall()

        for i in raw_logs:
            raw_log = i[5]
            program = raw_log['_COMM']
            hostname = i[2]
            pid = raw_log['_PID']
            raw_log = i[5]
           # print(raw_log)
            logsource = "journald"
            jcursor = i[7]
           # print(program, hostname, pid, logsource, jcursor)
            eventTimestamp = raw_log['__REALTIME_TIMESTAMP']
            message = raw_log['MESSAGE']

            print(message)


parse_rawlog()
