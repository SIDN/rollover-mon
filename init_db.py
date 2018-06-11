import sqlite3

from misc.config import config

def connect_db():
    return sqlite3.connect(config['DATABASE']['db_path'])

def init_table():

    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute('''CREATE TABLE measurements 
                    (msm_id int PRIMARY KEY, 
                    monitoring_goal text, 
                    query_type text, 
                    target text, 
                    ts int, 
                    running bool);''')

    connection.commit()

    connection.close()

init_table()