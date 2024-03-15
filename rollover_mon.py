import logging
from datetime import datetime
import analysis
import ripe_interface
from misc.config import config
from pathlib import Path

from misc.argparser import parser

log_level_info = {'DEBUG': logging.DEBUG,
                  'INFO': logging.INFO,
                  'WARNING': logging.WARNING,
                  'ERROR': logging.ERROR,
                  }


def parse_args(args):
    monitoring_target = args.target
    record = None
    action = None
    json_output = False
    start_date = None
    stop_date = None
    plot = None
    silent = False

    if (monitoring_target != "pubdelay" and monitoring_target != "propdelay"
            and monitoring_target != "trustchain" and monitoring_target != 'groundtruth'):
        print("Monitoring target must be either 'pubdelay', 'propdelay', 'trustchain' or 'groundtruth'.")
        raise AttributeError("Monitoring target must be either 'pubdelay', 'propdelay', 'trustchain' or 'groundtruth'.")

    if monitoring_target == "pubdelay" or monitoring_target == "propdelay":
        if args.record is None:
            print("Option '--record' required if target is 'pubdelay' or 'propdelay'.")
            raise AttributeError("Option '--record' required if target is 'pubdelay' or 'propdelay'")
        else:
            if args.record == 'dnskey' or args.record == 'ds':
                record = args.record
            else:
                print("'record' must be 'dnskey' 'ds' if 'target' is 'pubdelay' or 'propdelay'")
                raise AttributeError(
                    "'record' must be 'dnskey' or 'ds' if 'target' is 'pubdelay' or 'propdelay'")

    if monitoring_target != 'groundtruth':
        if args.start is True:
            action = 'start'
        elif args.stop is True:
            action = 'stop'
        elif args.status is True:
            action = 'status'
            json_output = args.json
        else:
            print("Action required")
            raise AttributeError("Action required")

    start_date = args.start_date
    stop_date = args.stop_date

    if start_date is not None:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d %H:%M')
        except Exception as e:
            print("'start-date' must have format Y-m-d H:M")
            raise e
    if stop_date is not None:
        try:
            stop_date = datetime.strptime(stop_date, '%Y-%m-%d %H:%M')
        except Exception as e:
            print("'end-date' must have format Y-m-d H:M")
            raise e

    if args.silent is True:
        silent = True

    return monitoring_target, record, action, json_output, start_date, stop_date, plot, silent


def main():
    logging.basicConfig(level=log_level_info[config['OUTPUT']['loglevel']])

    Path(config['OUTPUT']['figures']+'/servers').mkdir(parents=True, exist_ok=True)


    args = parser.parse_args()
    try:
        monitoring_target, record, action, json_output, start_date, stop_date, plot, silent = parse_args(args)
    except Exception as e:
        print(e)
        return

    if action == 'start':
        ripe_interface.create_measurements(monitoring_target, record, start_date, stop_date)

    elif action == 'stop':
        success = ripe_interface.stop_measurements(monitoring_target, record)
        if success:
            print('Every measurement stopped successfully.')
        else:
            print('Could not stop measurements. No measurement running or try again.')

    elif action == 'status':
        results = ripe_interface.collect_measurement_results(monitoring_target, record, start_date, stop_date)
        if results is not None:
            analysis.get_state(results, monitoring_target, details=json_output, figure=True)

    elif monitoring_target == 'groundtruth':
        results = ripe_interface.collect_measurement_results('trustchain', record, start_date, stop_date)
        if results is not None:
            analysis.get_state(results, 'trustchain', details=False, figure=False, groundtruth=True)


if __name__ == '__main__':
    main()
