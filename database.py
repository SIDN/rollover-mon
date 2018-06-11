import sqlite3
import time

from misc.config import config

def connect_db():
    return sqlite3.connect(config['DATABASE']['db_path'])

def init_measurement(msm_id, monitoring_goal, query_type, target):
    """Inserts new measurements to DB."""

    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute('INSERT INTO measurements VALUES (?, ?, ?, ?, ?, ?)', (msm_id, monitoring_goal, query_type, target, int(time.time()), True))

    connection.commit()

    connection.close()

def get_measurements(monitoring_goal, query_type, running):
    """Gets the measurements from the DB (only running or all)."""

    connection = connect_db()
    cursor = connection.cursor()

    if monitoring_goal != 'trustchain':
        if running:
            cursor.execute('SELECT msm_id, monitoring_goal, query_type, target FROM measurements WHERE running  = 1 and monitoring_goal = ? and query_type = ?',
             (monitoring_goal, query_type))
        else:
            cursor.execute('SELECT msm_id, monitoring_goal, query_type, target FROM measurements WHERE monitoring_goal = ? and query_type = ?',
             (monitoring_goal, query_type))
    else:
        if running:
            cursor.execute('SELECT msm_id, monitoring_goal, query_type, target FROM measurements WHERE running = 1 and monitoring_goal = ?',
             (monitoring_goal,))
        else:
            cursor.execute('SELECT msm_id, monitoring_goal, query_type, target FROM measurements WHERE monitoring_goal = ?',
             (monitoring_goal,))

    msm_ids = []
    msm_attributes = {}
    rows = cursor.fetchall()
    for row in rows:
        msm_ids.append(row[0])
        msm_attributes[row[0]] = [row[1], row[2], row[3]]    

    connection.close()
    return msm_ids, msm_attributes  


def stop_measurement(msm_id):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute('UPDATE measurements SET running = 0 WHERE msm_id = ?', (msm_id, ))

    connection.commit()

    connection.close()

