import datetime as dt
import time
import logging
from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasStopRequest, AtlasResultsRequest
from misc.config import config
import database


def get_targets_from_config(ipv, child=True):
    targets = []
    relationship = 'CHILDREN'
    if not child:
        relationship = 'PARENTS'

    for ns in config[relationship]:
        for ip in config[relationship][ns].split(','):
            if ':' in ip and ipv == 6:
                targets.append(ip.strip())
            elif ':' not in ip and ipv == 4:
                targets.append(ip.strip().replace(',', ''))

    return targets


def create_measurements(monitoring_goal, query_type, start_date, stop_date):
    """Creates new RIPE Atlas measurements and submits it via the RIPE Atlas API."""

    measurements = []
    targets = []
    if monitoring_goal == 'pubdelay':

        if query_type == 'dnskey' or query_type == 'rrsig':
            targets_ipv4 = get_targets_from_config(4)
            targets_ipv6 = get_targets_from_config(6)

        else:

            targets_ipv4 = get_targets_from_config(4, child=False)
            targets_ipv6 = get_targets_from_config(6, child=False)

        for target in targets_ipv4:
            if len(target) > 0:
                targets.append(target.strip())
                measurements.append(
                    create_measurement(monitoring_goal, target.strip(), query_type.upper(), 4, False, False))

        for target in targets_ipv6:
            if len(target) > 0:
                targets.append(target.strip())
                measurements.append(
                    create_measurement(monitoring_goal, target.strip(), query_type.upper(), 6, False, False))

        query_types = [query_type] * len(targets)

    if monitoring_goal == 'propdelay':
        query_types = [query_type] * 4
        targets = [4, 6, 4, 6]

        measurements.append(create_measurement(monitoring_goal, None, query_type.upper(), 4, True, False))
        measurements.append(create_measurement(monitoring_goal, None, query_type.upper(), 6, True, False))

    if monitoring_goal == 'trustchain':
        query_types = ['valid', 'valid', 'bogus', 'bogus']
        targets = [4, 6, 4, 6]

        measurements.append(
            create_measurement(monitoring_goal, config['MEASUREMENTS']['trust_chain_valid'], 'A', 4, True, True))
        measurements.append(
            create_measurement(monitoring_goal, config['MEASUREMENTS']['trust_chain_valid'], 'AAAA', 6, True,
                               True))
        measurements.append(
            create_measurement(monitoring_goal, config['MEASUREMENTS']['trust_chain_bogus'], 'A', 4, True, True))
        measurements.append(
            create_measurement(monitoring_goal, config['MEASUREMENTS']['trust_chain_bogus'], 'AAAA', 6, True,
                               True))

    # Define timing of measurements
    if start_date is None:
        start_date = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=1)
    elif start_date < dt.datetime.now(dt.UTC):
        print("'start-date' must be after current time")
        return

    if stop_date is not None:
        if stop_date < start_date:
            print("'stop-date' must be after 'start_date'")
            return

        elif stop_date < dt.datetime.now(dt.UTC):
            print("'stop-date' must be after current time")
            return

    sources = create_source()

    bill_to = config['RIPE']['bill_to']

    if bill_to is not None:
        logging.info(f'Charge credits to {bill_to}.')
        atlas_request = AtlasCreateRequest(
            start_time=start_date,
            stop_time=stop_date,
            key=config['RIPE']['api_key'],
            measurements=measurements,
            sources=[sources],
            bill_to=bill_to
        )

    else:
        atlas_request = AtlasCreateRequest(
            start_time=start_date,
            stop_time=stop_date,
            key=config['RIPE']['api_key'],
            measurements=measurements,
            sources=[sources],
        )

    is_success, response = atlas_request.create()

    if is_success:
        print('Measurements created successfully.')
        for i in range(len(response['measurements'])):
            database.init_measurement(response['measurements'][i], monitoring_goal, query_types[i], targets[i])
    else:
        print('RIPE Atlas API Error:', response)

    return is_success


def stop_measurements(monitoring_goal, query_type):
    """Stops running RIPE Atlas measurements."""

    msm_ids, msm_attributes = database.get_measurements(monitoring_goal, query_type, True)
    success_counter = 0

    for msm_id in msm_ids:
        atlas_request = AtlasStopRequest(msm_id=msm_id, key=config['RIPE']['api_key'])

        is_success, response = atlas_request.create()
        # print(is_success, response)
        if is_success:
            database.stop_measurement(msm_id)
            success_counter += 1

    if success_counter == len(msm_ids):
        return True
    else:
        return False


def collect_measurement_results(monitoring_goal, query_type, start_date, stop_date):
    """Collects measurement results from RIPE Atlas."""
    msm_data = []
    msm_ids, msm_attributes = database.get_measurements(monitoring_goal, query_type, None)
    if start_date is None:
        stop_date = dt.datetime.now(dt.UTC)
        start_date = stop_date - dt.timedelta(minutes=140)
    if stop_date is None:
        stop_date = dt.datetime.now(dt.UTC)

    for msm_id in msm_ids:
        query_type = msm_attributes[msm_id][1]
        latest_ts = database.get_latest_stored_data(
            msm_id, monitoring_goal, query_type, msm_attributes[msm_id][2], msm_attributes[msm_id][3])

        # Check if last stored measurement is older than stop data
        fetch_from_ripe = False
        if latest_ts is not None and len(latest_ts) > 0:
            logging.info(f'Stored measurements exist for {msm_id}')
            if latest_ts[-1] < stop_date.timestamp():
                logging.info(f'Stored measurements for {msm_id} are not up to date. '
                             f'Stored: {dt.datetime.fromtimestamp(latest_ts[-1], dt.UTC)}, Stop Date: {stop_date}')
                fetch_from_ripe = True
                # Always look 5 minutes into the past to fetch late results
                ripe_start_date = latest_ts[-1] - 60 * 5
        else:
            fetch_from_ripe = True
            # If DB is empty, fetch data from the start
            ripe_start_date = msm_attributes[msm_id][3]

        if fetch_from_ripe:
            logging.info(f'Fetching measurements from RIPE for {msm_id}')
            logging.info(f'Start date: {dt.datetime.fromtimestamp(ripe_start_date, dt.UTC)}')
            kwargs = {
                "msm_id": msm_id,
                "start": dt.datetime.fromtimestamp(ripe_start_date, dt.UTC),
                "stop": stop_date
            }

            is_success, results = AtlasResultsRequest(**kwargs).create()

            if is_success:
                database.store_measurements_in_db(msm_id, monitoring_goal, query_type, msm_attributes[msm_id][2],
                                                  results)

        msm_data += database.get_stored_measurements(msm_id, monitoring_goal, query_type, msm_attributes[msm_id][2],
                                                     start_date.timestamp(), stop_date.timestamp())

    return msm_data


def create_measurement(monitoring_goal, target, query_type, af, use_probe_resolver, monitor_trust_chain):
    """Creates one single DNS measurement."""

    if use_probe_resolver:
        # Monitor Trust Chain
        if monitor_trust_chain:
            description = config['ROLLOVER']['ZONE'] + '_' + monitoring_goal + '_' + target + '_' + str(
                int(time.time()))
            dns = Dns(af=af,
                      use_probe_resolver=True,
                      query_class='IN',
                      query_type=query_type,
                      query_argument=target,
                      interval=int(config['TTLS']['ttl_dnskey']) / 2,
                      spread=int(config['TTLS']['ttl_dnskey']) / 2 - 20,
                      udp_payload_size=1232,
                      description=description)

        # Monitor Propagation Delay
        else:
            description = config['ROLLOVER'][
                              'ZONE'] + '_' + monitoring_goal + '_' + query_type + '_use_probe_resolver_' + str(
                int(time.time()))
            interval = int(config['TTLS']['ttl_' + query_type])
            dns = Dns(af=af,
                      use_probe_resolver=True,
                      query_class='IN',
                      query_type=query_type,
                      query_argument=config['ROLLOVER']['ZONE'],
                      interval=interval,
                      spread=interval - 20,
                      udp_payload_size=1232,
                      description=description)

    # Monitor Publication Delay 
    else:
        description = config['ROLLOVER']['ZONE'] + '_' + monitoring_goal + '_' + query_type + '_' + target + '_' + str(
            int(time.time()))
        dns = Dns(af=af,
                  target=target,
                  query_class='IN',
                  query_type=query_type,
                  query_argument=config['ROLLOVER']['ZONE'],
                  interval=int(config['MEASUREMENTS']['msm_frequency_publication_delay']),
                  spread=int(config['MEASUREMENTS']['msm_frequency_publication_delay']) - 20,
                  udp_payload_size=1232,
                  description=description)

    return dns


def create_source():
    """Selects the RIPE Atlas probes for the measurements."""

    # Check if measurement exists and if yes, reuse probes
    last_msm = database.get_oldest_measurement()
    if last_msm is not None:
        logging.info(f'Reusing probes from measurement {last_msm[0]}')
        value = int(last_msm[0])
        msm_type = 'msm'

    else:
        value = "WW"
        msm_type = "area"

    if config['RIPE']['probes'] is not None:
        if config['RIPE']['probes'] == 'all':
            requested = 10000
        else:
            requested = int(config['RIPE']['probes'])


        # if config['RIPE']['probe_ids'] is not None:
        #     probe_selector = 'probes'
        #     value = []
        #     for probe_id in config['RIPE']['probe_ids'].split(','):
        #         value.append(probe_id.strip())
        #
        # elif config['RIPE']['as_nr'] is not None:
        #     probe_selector = 'asn'
        #     value = int(config['RIPE']['as_nr'])
        #
        # elif config['RIPE']['country'] is not None:
        #     probe_selector = 'country'
        #     value = config['RIPE']['country']

    return AtlasSource(requested=requested,
                       type=msm_type,
                       value=value)
