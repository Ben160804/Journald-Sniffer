from systemd import journal
from connection import connectdb, closedbconn
from datetime import datetime
from json_guard import is_json_safe
import json


def read():
    journalreader = journal.Reader()

    journalreader.add_match(
        "_EXE=/usr/bin/su",
        "_EXE=/usr/bin/sudo",
        "_EXE=/usr/lib/ssh/sshd-session"
    )

    conn = connectdb()

    cursor = conn.cursor()
    cursor.execute('select 1 from raw_logs')

    logs = cursor.fetchone()
    if logs is None:
        for i in journalreader:
            # sob kotar program
            # hostname , ingestion time, pid, raw_msg, log _source
            # journal cursor
            prog = i['_COMM'] if i['_COMM'] else None
            hostName = i['_HOSTNAME'] if i['_HOSTNAME'] else None
            processID = i['_PID']
            eventTimestamp = i['__REALTIME_TIMESTAMP']
            rawMsg = json.dumps(is_json_safe(i))
            logSource = 'journald'
            ingestionTimestamp = datetime.now()
            jCursor = i['__CURSOR']

            cursor.execute("""INSERT INTO raw_logs(
                program,
                hostname,
                ingestion_time,
                event_time,
                pid,
                raw_msg,
                log_source,
                journal_cursor
            )VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""", (
                           prog,
                           hostName,
                           ingestionTimestamp,
                           eventTimestamp,
                           processID,
                           rawMsg,
                           logSource,
                           jCursor
                           )
                           )
            conn.commit()
    else:
        flag = 0
        # jodi already kichu thake tale last non null journal cursor khujbo
        cursor.execute("""
        SELECT journal_cursor FROM raw_logs WHERE
        journal_cursor IS NOT NULL ORDER BY id DESC
        LIMIT 1;
        """)

        # fetchone returns a tuple,
        # fetches from the value attached to the cursor from last execute
        f_jCursor = cursor.fetchone()[0]

        for i in journalreader:
            # sob kotar program
            # hostname , ingestion time, pid, raw_msg, log _source
            # journal cursor
            prog = i['_COMM'] if i['_COMM'] else None
            hostName = i['_HOSTNAME'] if i['_HOSTNAME'] else None
            processID = i['_PID']
            rawMsg = json.dumps(is_json_safe(i))
            logSource = 'journald'
            eventTimestamp = i['__REALTIME_TIMESTAMP']
            ingestionTimestamp = datetime.now()
            jCursor = i['__CURSOR']

            if flag == 0:
                if jCursor != f_jCursor:
                    continue
                flag = 1
                continue

            cursor.execute("""INSERT INTO raw_logs(
                program,
                hostname,
                ingestion_time,
                event_time,
                pid,
                raw_msg,
                log_source,
                journal_cursor
            )VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""", (
                           prog,
                           hostName,
                           ingestionTimestamp,
                           eventTimestamp,
                           processID,
                           rawMsg,
                           logSource,
                           jCursor
                           )
                           )
        conn.commit()

    cursor.close()
    closedbconn()

    '''while (True):
        journalreader.seek_realtime(datetime.now())

        for i in journalreader:
            print(i)'''
    # filter : "_EXE" : "/usr/lib/ssh/sshd-session",
    #          "_EXE" : "/usr/bin/sudo",
    #          "_EXE" : "/usr/bin/su",

    '''
    #parser logic 
    groups = {}

    for i in journalreader:
        if (i['_HOSTNAME'], i['_PID']) in groups:
            groups[(i['_HOSTNAME'], i['_PID'])].append(i)
        else:
            groups[(i['_HOSTNAME'], i['_PID'])] = []
            groups[(i['_HOSTNAME'], i['_PID'])].append(i)

        print("hostname="+i['_HOSTNAME'],
        "Syslog identifier="+i['SYSLOG_IDENTIFIER'],
        "Program="+i['_CMDLINE'],
        "Pid ="+str(i['_PID']), "message="+i['MESSAGE'],
        "timestamp="+str(i['__REALTIME_TIMESTAMP']), "raw_msg="+str(i))
        '''

    '''
    for i, j in groups:
        print(i, j, "=", groups[(i, j)])
        print('\n')

    '''
