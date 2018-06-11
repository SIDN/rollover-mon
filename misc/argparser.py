import argparse

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

parser.add_argument("target", help="Defines, what you want to monitor. Options are: 'pubdelay', 'propdelay' or 'trustchain'.")
parser.add_argument("--record", help="'dnskey', 'rrsig' or 'ds'. Required when target is 'pubdelay' or 'propdelay'.")

group.add_argument("--start", help="Start monitoring", action="store_true")
group.add_argument("--stop", help="Stop monitoring", action="store_true")
group.add_argument("--status", help="Get monitoring state (of the last 60 minutes by default)", action="store_true")

parser.add_argument("--details", help="Returns detailed monitoring state as JSON.", action="store_true")
parser.add_argument("--start-date", help="Date of the first measurement (Y-m-d H:M 24h). Only in combination with --status")
parser.add_argument("--stop-date", help="Date of the last measurement. Only in combination with --status")
