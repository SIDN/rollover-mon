from datetime import datetime, timedelta
import time

from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasStopRequest, AtlasResultsRequest

from misc.config import config
import database
import analysis

def create_measurements(monitoring_goal, query_type, start_date, stop_date):
    """Creates new RIPE Atlas measurements and submits it via the RIPE Atlas API."""



    measurements = []
    targets = []
    if monitoring_goal == 'pubdelay':
    
        if query_type == 'dnskey' or query_type == 'rrsig':
            targets_ipv4 = config['NAMESERVERS']['ips_child_ipv4']
            targets_ipv6 = config['NAMESERVERS']['ips_child_ipv6']
        else:
            targets_ipv4 = config['NAMESERVERS']['ips_parent_ipv4']
            targets_ipv6 = config['NAMESERVERS']['ips_parent_ipv6']

        targets_ipv4 = targets_ipv4.split(',')
        targets_ipv6 = targets_ipv6.split(',')

        for target in targets_ipv4:
            targets.append(target.strip())
            measurements.append(create_measurement(monitoring_goal, target.strip(), query_type.upper(), True, 4, False, False))

        for target in targets_ipv6:
            targets.append(target.strip())
            measurements.append(create_measurement(monitoring_goal, target.strip(), query_type.upper(), True, 6, False, False))

        query_types = [query_type]*4


    if monitoring_goal == 'propdelay':
        query_types = [query_type]*4
        targets = [4, 6, 4, 6]
        
        measurements.append(create_measurement(monitoring_goal, None, query_type.upper(), True, 4, True, False))
        measurements.append(create_measurement(monitoring_goal, None, query_type.upper(), True, 6, True, False))

    
    if monitoring_goal == 'trustchain':
        query_types = ['valid', 'valid', 'bogus', 'bogus']
        targets = [4, 6, 4, 6]
        
        measurements.append(create_measurement(monitoring_goal, config['MEASUREMENTS']['trust_chain_valid'], 'A', True, 4, True, True))
        measurements.append(create_measurement(monitoring_goal, config['MEASUREMENTS']['trust_chain_valid'], 'AAAA', True, 6, True, True))
        measurements.append(create_measurement(monitoring_goal, config['MEASUREMENTS']['trust_chain_bogus'], 'A', True, 4, True, True))
        measurements.append(create_measurement(monitoring_goal, config['MEASUREMENTS']['trust_chain_bogus'], 'AAAA', True, 6, True, True))


    sources = create_source()

    # Define timing of measurements
    if start_date is None:
        start_date = datetime.utcnow()
    elif start_date < datetime.utcnow():
        print("'start-date' must be after current time")
        return

    if stop_date is not None:    
        if stop_date < start_date:
            print("'stop-date' must be after 'start_date'")
            return

        elif stop_date < datetime.utcnow():
            print("'stop-date' must be after current time")
            return

    atlas_request = AtlasCreateRequest(
         start_time=start_date,
         stop_time=stop_date,
         key=config['RIPE']['api_key'],
         measurements=measurements,
         sources=[sources]
        )   

    is_success, response = atlas_request.create()

    if is_success:
        print('Measurements created successfully.')
        for i in range(len(response['measurements'])):
            database.init_measurement(response['measurements'][i], monitoring_goal, query_types[i], targets[i])

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
            success_counter+=1    
             
    if success_counter == len(msm_ids):
        return True
    else:
        return False


def collect_measurement_results(monitoring_goal, query_type, details, start_date, stop_date):
    """Collects measurement results from RIPE Atlas."""

    msm_ids, msm_attributes = database.get_measurements(monitoring_goal, query_type, None)  


    if start_date is None:
        stop_date = datetime.utcnow() 
        start_date = stop_date - timedelta(minutes = 60)
    elif start_date is not None and stop_date is None:
        stop_date =  datetime.utcnow()



    msm_results = {}
       
    for msm_id in msm_ids:
        kwargs = {
           "msm_id": msm_id,
           "start": start_date,
           "stop": stop_date
        }

        is_success, results = AtlasResultsRequest(**kwargs).create()

        if is_success:
            msm_results[msm_id] = results

    if len(msm_results) > 0:
    
        if monitoring_goal == 'pubdelay' or monitoring_goal == 'propdelay':
            analysis.get_state_publication_and_propagation(msm_results, msm_attributes, start_date, stop_date, details)
        else:
            analysis.get_state_trust_chain(msm_results, msm_attributes, start_date, stop_date, details)



          

def create_measurement(monitoring_goal, target, query_type, direct, af, use_probe_resolver, monitor_trust_chain):
    """Creates one single DNS measurement."""

    if use_probe_resolver:
         # Monitor Trust Chain  
         if monitor_trust_chain:
             description = config['ROLLOVER']['ZONE']+'_'+monitoring_goal+'_'+target+'_'+str(int(time.time()))
             dns = Dns(af = af,
                  use_probe_resolver = True,
                  query_class = 'IN',
                  query_type = query_type,
                  query_argument = target,
                  interval = int(config['TTLS']['ttl_dnskey']),
                  spread = int(config['TTLS']['ttl_dnskey'])-20,
                  description = description)

         # Monitor Propagation Delay
         else: 
             description = config['ROLLOVER']['ZONE']+'_'+monitoring_goal+'_'+query_type+'_use_probe_resolver_'+str(int(time.time()))
             interval = int(config['TTLS']['ttl_'+query_type])
             dns = Dns(af = af,
                  use_probe_resolver = True,
                  query_class = 'IN',
                  query_type = query_type,
                  query_argument = config['ROLLOVER']['ZONE'],
                  interval = interval,
                  spread = interval-20,
                  description = description)

    # Monitor Publication Delay 
    else:
        description = config['ROLLOVER']['ZONE']+'_'+monitoring_goal+'_'+query_type+'_'+target+'_'+str(int(time.time()))
        dns = Dns(af = af, 
                  target = target, 
                  query_class = 'IN', 
                  query_type = query_type, 
                  query_argument = config['ROLLOVER']['ZONE'],
                  interval = int(config['MEASUREMENTS']['msm_frequency_publication_delay']),
                  spread = int(config['MEASUREMENTS']['msm_frequency_publication_delay'])-20,
                  description = description)

    return dns


def create_source():
    """Selects the RIPE Atlas probes for the measurements."""

    # TO DO: Continent filter
    probe_selector = None
    requested = 0    
    value = "WW"
    probe_selector = "area"

    if config['RIPE']['probes'] is not None:
        if config['RIPE']['probes'] == 'all':
            requested = 10000
        else:
            requested = int(config['RIPE']['probes']) 

        if config['RIPE']['probe_ids'] is not None:
            probe_selector = 'probes'
            value = []
            for probe_id in config['RIPE']['probe_ids'].split(','):
                value.append(probe_id.strip())

        elif config['RIPE']['as_nr'] is not None:
            probe_selector = 'asn'
            value = int(config['RIPE']['as_nr'])

        elif config['RIPE']['country'] is not None:
            probe_selector = 'country'
            value = config['RIPE']['country']

        #print(requested, probe_selector, value)
        return AtlasSource(requested = requested, 
                           type=probe_selector, 
                           value = value)

