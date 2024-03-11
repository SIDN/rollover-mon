import sqlite3
from misc.config import config
import logging

logging.basicConfig(level=logging.DEBUG)


def connect_db():
    return sqlite3.connect(config['DATABASE']['db_path'])


def init_table():
    connection = connect_db()
    cursor = connection.cursor()

    try:
        cursor.execute('''CREATE TABLE measurements 
                        (msm_id int PRIMARY KEY, 
                        monitoring_goal text, 
                        query_type text, 
                        target text, 
                        ts int, 
                        running bool);''')

        connection.commit()
    except sqlite3.OperationalError as e:
        logging.error(e)

    try:
        cursor.execute('''CREATE TABLE measurement_data (
                        msm_id int, 
                        monitoring_goal text, 
                        query_type text, 
                        target text, 
                        ts int, 
                        vp text,
                        vals text,
                        PRIMARY KEY (msm_id, monitoring_goal, query_type, target, ts, vp, vals)
                        );''')
        connection.commit()
    except sqlite3.OperationalError as e:
        logging.error(e)

    try:
        cursor.execute('''CREATE TABLE excluded_vps (
                           vp text,
                           PRIMARY KEY (vp)
                           );''')
        connection.commit()

    except sqlite3.OperationalError as e:
        logging.error(e)

    connection.close()


init_table()
