import psycopg2
from dbconfig import get_db_conf
global conn
conn = None


def connectdb():
    global conn
    # first we declare a Connector
    try:
        conn = psycopg2.connect(**get_db_conf())
        return conn
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)


def closedbconn():
    global conn
    if conn is not None:

        conn.close()
        print("Connection closed")
    else:
        print("connection closed already")
