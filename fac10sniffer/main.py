# cant be run in a venv python-systemd is a distro package
from ingestor import read
from connection import connectdb, closedbconn

# connectdb()
# closedbconn()
read()

'''
    goals:
    parse the required fields we need based on raw_logs

    connect to db 

    create a cursor

    get the last journal cursor 

    execute recursive inserts based on last journal cursor

    close cursor 

    close db connection

'''
