import sqlite3
import time
from ripe.atlas.sagan import DnsResult
from misc.tools import calc_keyid
from misc.config import config
import logging
import json

log_level_info = {'DEBUG': logging.DEBUG,
                  'INFO': logging.INFO,
                  'WARNING': logging.WARNING,
                  'ERROR': logging.ERROR,
                  }


def connect_db():
    return sqlite3.connect(config['DATABASE']['db_path'])


def init_measurement(msm_id, monitoring_goal, query_type, target):
    """Inserts new measurements to DB."""

    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute('INSERT INTO measurements VALUES (?, ?, ?, ?, ?, ?)',
                   (msm_id, monitoring_goal, query_type, target, int(time.time()), True))

    connection.commit()

    connection.close()


def get_measurements(monitoring_goal, query_type, running):
    """Gets the measurements from the DB (only running or all)."""

    connection = connect_db()
    cursor = connection.cursor()

    if monitoring_goal != 'trustchain':
        if running:
            cursor.execute(
                'SELECT msm_id, monitoring_goal, query_type, target, ts FROM measurements WHERE running  = 1 and monitoring_goal = ? and query_type = ?',
                (monitoring_goal, query_type))
        else:
            cursor.execute(
                'SELECT msm_id, monitoring_goal, query_type, target, ts FROM measurements WHERE monitoring_goal = ? and query_type = ?',
                (monitoring_goal, query_type))
    else:
        if running:
            cursor.execute(
                'SELECT msm_id, monitoring_goal, query_type, target, ts  FROM measurements WHERE running = 1 and monitoring_goal = ?',
                (monitoring_goal,))
        else:
            cursor.execute(
                'SELECT msm_id, monitoring_goal, query_type, target, ts FROM measurements WHERE monitoring_goal = ?',
                (monitoring_goal,))

    msm_ids = []
    msm_attributes = {}
    rows = cursor.fetchall()
    for row in rows:
        msm_ids.append(row[0])
        msm_attributes[row[0]] = [row[1], row[2], row[3], row[4]]

    connection.close()
    return msm_ids, msm_attributes


def get_stored_measurements(msm_id, monitoring_goal, query_type, target, start_date, end_date):
    with connect_db() as connection:
        cursor = connection.cursor()

        cursor.execute('SELECT msm_id, monitoring_goal, query_type, target, ts, vp, vals FROM measurement_data '
                       'WHERE msm_id = ? and monitoring_goal = ? and query_type = ? and target = ? and ts >= ? and ts <= ?'
                       'AND vp not in ('
                       'SELECT vp FROM excluded_vps'
                       ')'
                       'ORDER BY ts',
                       (msm_id, monitoring_goal, query_type, target, start_date, end_date))

        return cursor.fetchall()


def get_latest_stored_data(msm_id, monitoring_goal, query_type, target, start_date):
    with connect_db() as connection:
        cursor = connection.cursor()
        cursor.execute('SELECT ts FROM measurement_data '
                       'WHERE msm_id = ? and monitoring_goal = ? and query_type = ? and target = ? and ts >= ?'
                       'ORDER BY ts DESC',
                       (msm_id, monitoring_goal, query_type, target, start_date))

        return cursor.fetchone()


def store_measurements_in_db(msm_id, monitoring_goal, query_type, target, msm_data):
    logging.info('Storing measurement into DB')
    logging.getLogger().setLevel(logging.ERROR)

    with connect_db() as connection:
        cursor = connection.cursor()

        for msm in msm_data:
            dns_result = DnsResult(msm)

            if ~dns_result.is_error:

                for response in dns_result.responses:
                    # if response.abuf is not None and not response.is_error:
                    if response.abuf is not None:

                        vp = str(dns_result.probe_id) + '_' + response.destination_address
                        ts = dns_result.created_timestamp

                        if monitoring_goal == 'pubdelay' or monitoring_goal == 'propdelay':
                            for answer in response.abuf.answers:
                                vals = {}
                                if 'Type' in answer.raw_data:
                                    if answer.raw_data['Type'] == 'DNSKEY' and answer.name == config['ROLLOVER'][
                                        'zone']:
                                        vals['algorithm'] = answer.algorithm
                                        vals['protocol'] = answer.protocol
                                        vals['flags'] = answer.flags
                                        vals['key_tag'] = calc_keyid(answer.flags, answer.protocol,
                                                                     answer.algorithm, answer.key)

                                    elif (answer.raw_data['Type'] == 'DS') and answer.name == config['ROLLOVER'][
                                        'zone']:
                                        vals['key_tag'] = answer.raw_data['Tag']

                                    if len(vals) > 0:
                                        logging.debug((msm_id, monitoring_goal, query_type, target, ts, vp, str(vals)))
                                        cursor.execute(
                                            'INSERT OR IGNORE INTO measurement_data VALUES (?, ?, ?, ?, ?, ?, ?)',
                                            (msm_id, monitoring_goal, query_type, target, ts, vp, json.dumps(vals)))

                        elif monitoring_goal == 'trustchain':
                            vals = {}
                            return_code = response.abuf.header.return_code
                            vals['return_code'] = return_code

                            if len(vals) > 0:
                                logging.debug((msm_id, monitoring_goal, query_type, target, ts, vp, str(vals)))
                                cursor.execute('INSERT OR IGNORE INTO measurement_data VALUES (?, ?, ?, ?, ?, ?, ?)',
                                               (msm_id, monitoring_goal, query_type, target, ts, vp, json.dumps(vals)))

            connection.commit()

    logging.getLogger().setLevel(log_level_info[config['OUTPUT']['loglevel']])


def store_excluded_vps(vps):
    logging.info('Storing excluded VPs into DB')
    with connect_db() as connection:
        cursor = connection.cursor()
        for vp in vps:
            cursor.execute('INSERT OR IGNORE INTO excluded_vps (vp) VALUES (?)',
                           (vp,))

        connection.commit()


def get_oldest_measurement():
    logging.info('Getting oldest measurement ID')
    with connect_db() as connection:
        cursor = connection.cursor()
        cursor.execute('SELECT msm_id from measurements ORDER BY ts')

        return cursor.fetchone()



def stop_measurement(msm_id):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute('UPDATE measurements SET running = 0 WHERE msm_id = ?', (msm_id,))

    connection.commit()

    connection.close()
