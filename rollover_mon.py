import logging
from datetime import datetime

import ripe_interface

from misc.argparser import parser 


logging.basicConfig(level=logging.ERROR)

def parse_args(args):
    """Parses the necessary arguments and returns them to the main function."""

    monitoring_target = args.target
    record = None
    action = None
    details = False
    start_date = None
    stop_date = None
    plot = None

    if (monitoring_target != "pubdelay" and monitoring_target != "propdelay" and  monitoring_target != "trustchain"):
        print("Monitorint target must be either 'pubdelay', 'propdelay' or 'trustchain'.")
        raise AttributeError("Monitorint target must be either 'pubdelay', 'propdelay' or 'trustchain'.")

    if monitoring_target == "pubdelay" or monitoring_target == "propdelay":
        if args.record is None:
            print("Option '--record' required if target is 'pubdelay' or 'propdelay'.")
            raise AttributeError("Option '--record' required if target is 'pubdelay' or 'propdelay'")
        else:
            if args.record == 'dnskey' or args.record == 'rrsig' or args.record == 'ds':
                record = args.record
            else:
                print("'record' must be 'dnskey', 'rrsig' or 'ds' if 'target' is 'pubdelay' or 'propdelay'")
                raise AttributeError("'record' must be 'dnskey', 'rrsig' or 'ds' if 'target' is 'pubdelay' or 'propdelay'")


    if args.start is True:
        action = 'start'
    elif args.stop is True:
        action = 'stop'
    elif args.status is True:
        action = 'status'
        details = args.details

    else:
        print("Action required")     
        raise AttributeError("Action required")  


    start_date = args.start_date
    stop_date = args.stop_date
    # plot = args.plot

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

    return monitoring_target, record, action, details, start_date, stop_date, plot


def main():
    args = parser.parse_args()
    try:
        monitoring_target, record, action, details, start_date, stop_date, plot = parse_args(args)
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
        ripe_interface.collect_measurement_results(monitoring_target, record, details, start_date, stop_date)


main()
