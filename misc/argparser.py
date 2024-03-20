import argparse

parser = argparse.ArgumentParser(description='Rollover Monitor CLI.')
group = parser.add_mutually_exclusive_group()

parser.add_argument("target", help="Defines, what you want to monitor. Options are: 'pubdelay', 'propdelay', 'trustchain' or 'groundtruth'.")
parser.add_argument("--record", help="'dnskey' or 'ds'. Required when target is 'pubdelay' or 'propdelay'.")

group.add_argument("--start", help="Start monitoring", action="store_true")
group.add_argument("--stop", help="Stop monitoring", action="store_true")
group.add_argument("--status", help="Get monitoring state (of the last 60 minutes by default)", action="store_true")
parser.add_argument("--silent", help="Hide output", action="store_true")

parser.add_argument("--json", help="Returns monitoring state in json.", action="store_true")
parser.add_argument("--start-date", help="Date of the first measurement (Y-m-d H:M 24h). Only in combination with --status and --start")
parser.add_argument("--stop-date", help="Date of the last measurement. Only in combination with --status and --start")