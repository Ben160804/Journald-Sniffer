from dotenv import load_dotenv
import os


load_dotenv()


def get_db_conf():
    # this should be exact by convention
    db = {
        "host": os.getenv("DB_HOST"),
        "dbname": os.getenv("DB_NAME"),
        "password": os.getenv("DB_PASS"),
        "user": os.getenv("DB_USER"),
    }

    return db
