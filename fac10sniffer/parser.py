from connection import connectdb, closedbconn
import ast

 

class raw_fact:
    __slots__= (
        "raw_id",
        "jcursor",
        "time",
        "program",
        "pid",
        "uid",
        "username",
        "src_ip",
        "message",
        "host_name",
    )

    def __init__(self,raw_id,jcursor,time,program,pid,uid,username,src_ip,message,host_name,):
        self.raw_id = raw_id
        self.jcursor = jcursor
        self.time = time
        self.program = program
        self.pid = pid
        self.uid = uid
        self.username = username
        self.src_ip = src_ip
        self.message = message
        self.host_name = host_name



distinct_progs = ['sudo', 'su', 'sshd-session']


def parse_rawlog():
    conn = connectdb()
    cursor = conn.cursor()
    print("REACHED A")

    cursor.execute('''
   select max(jcursor) from auth_logs;  
   ''') 
    last_derived_cursor = cursor.fetchone()[0]
    print(last_derived_cursor)
    if last_derived_cursor != None:
        cursor.execute('''
        select * from raw_logs where journal_cursor > %s order by journal_cursor asc;
        ''',last_derived_cursor)
        raw_logs = cursor.fetchall()
    else:
        cursor.execute('''
        select * from raw_logs;
                       ''')
        raw_logs = cursor.fetchall()
    buffer = {}
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
        src_ip = None
        username = None
        fact = raw_fact(raw_id = raw_id,
                        program = program,
                        host_name = host_name,
                        time = event_time,
                        pid = pid,
                        uid = uid,
                        src_ip = src_ip,
                        username = username,
                        jcursor = journal_cursor,
                        message = message,
                        )
        print(fact)
     

parse_rawlog()




