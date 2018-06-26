from collections import defaultdict 
#from matplotlib import pyplot as plt

from ripe.atlas.sagan import DnsResult
import pandas as pd

from misc.tools import calc_keyid
from misc.config import config



def get_state_publication_and_propagation(msm_results, msm_attributes, start_date, stop_date, details):
    """Processes the measurement results from RIPE Atlas
    for the publication and propagation delay.
    Prints the results as a string.
    """

    time_series = []

    for msm_id, attributes in msm_attributes.items():
        
        responses_counter_zsk = 0
        responses_counter_ksk = 0

        
        
        if attributes[0] == 'pubdelay':
            print('Monitoring {} of {} at {} ({} - {})'.format(
                attributes[0], attributes[1].upper(), attributes[2], 
                start_date.strftime('%Y-%m-%d %H:%M'), stop_date.strftime('%Y-%m-%d %H:%M')))
        else:
            print('Monitoring {} of {} (IPv{} ({} - {}))'.format(
                attributes[0], attributes[1].upper(), attributes[2], 
                start_date.strftime('%Y-%m-%d %H:%M'), stop_date.strftime('%Y-%m-%d %H:%M')))
        
        

        keys_zsk = defaultdict(int)
        keys_ksk = defaultdict(int)

        if msm_id in msm_results:
            for measurement in msm_results[msm_id]:

                dns_result = DnsResult(measurement)
                
                if ~dns_result.is_error:
                    
                    for response in dns_result.responses:
                        if response.abuf is not None:
                            for answer in response.abuf.answers:

                                if answer.raw_data['Type'] == 'DNSKEY' and answer.name == config['ROLLOVER']['zone']:           

                                    algorithm = answer.raw_data['Algorithm']
                                    protocol = answer.raw_data['Protocol']
                                    flags = answer.raw_data['Flags']
                                    key_tag = calc_keyid(flags, protocol, algorithm, answer.raw_data['Key'])
                                    created = dns_result.created

                                    if flags == 256:
                                        keys_zsk[key_tag]+=1
                                        responses_counter_zsk+=1
                                    elif flags == 257:
                                        keys_ksk[key_tag]+=1
                                        responses_counter_ksk+=1

                                    time_series.append([created, attributes[2], key_tag])

                                elif (answer.raw_data['Type'] == 'RRSIG' 
                                      and answer.raw_data['TypeCovered'] == 'DNSKEY'
                                      and answer.name == config['ROLLOVER']['zone']):

                                    responses_counter_zsk+=1

                                    created = dns_result.created
                                    key_tag = answer.raw_data['KeyTag']
                                    keys_zsk[key_tag]+=1

                                    time_series.append([created, attributes[2], key_tag])

                                elif (answer.raw_data['Type'] == 'DS') and answer.name == config['ROLLOVER']['zone']:

                                    responses_counter_zsk+=1

                                    created = dns_result.created
                                    key_tag = answer.raw_data['Tag']
                                    keys_zsk[key_tag]+=1

                                    time_series.append([created, attributes[2], key_tag])


            print('Key Tag\t# Observed (Share %)')
            for key in keys_zsk.keys():
                print('{}\t\t{} ({}%)'.format(key, keys_zsk[key], round(keys_zsk[key]/responses_counter_zsk*100,2)))

            for key in keys_ksk.keys():
                print('{}\t\t{} ({}%)'.format(key, keys_ksk[key], round(keys_ksk[key]/responses_counter_ksk*100,2)))


    if details:
        get_details(time_series, attributes)

    return 



def get_state_trust_chain(msm_results, msm_attributes, start_date, stop_date, plot):
    """Processes the measurement results from RIPE Atlas
    for the trust chain.
    Prints the results as a string.
    """

    vantage_point_state = {}


    for msm_id, attributes in msm_attributes.items():       

        for measurement in msm_results[msm_id]:

            dns_result = DnsResult(measurement)

            if ~dns_result.is_error:

                for response in dns_result.responses:

                    if response.abuf is not None:
                        probe_id = dns_result.probe_id
                        destination_address = response.destination_address
                        vantage_point_id = str(probe_id)+'_'+destination_address
                        created = dns_result.created

                        if vantage_point_id not in vantage_point_state:
                            vantage_point_state[vantage_point_id] = {'ipv4_valid': None, 'ipv4_bogus': None, 
                                                                        'ipv6_valid': None, 'ipv6_bogus': None}

                        return_code = response.abuf.header.return_code


                        if attributes[1] == 'valid':

                            if attributes[2] == '4':
                                vantage_point_state[vantage_point_id]['ipv4_valid'] = return_code

                            else:
                                vantage_point_state[vantage_point_id]['ipv6_valid'] = return_code

                        else:

                            if attributes[2] == '4':
                                vantage_point_state[vantage_point_id]['ipv4_bogus'] = return_code
                            else:
                                vantage_point_state[vantage_point_id]['ipv6_bogus'] = return_code




    ipv4_summary = defaultdict(int)
    ipv6_summary = defaultdict(int)

    total_summary = {'ipv4_valid': defaultdict(int), 'ipv4_bogus': defaultdict(int), 
                        'ipv6_valid': defaultdict(int), 'ipv6_bogus': defaultdict(int)}

    ipv4_measurements = 0
    ipv6_measurements = 0

    for vantage_point in vantage_point_state.keys():

        state = define_state(vantage_point_state[vantage_point]['ipv4_valid'], vantage_point_state[vantage_point]['ipv4_bogus'])
        ipv4_summary[state]+=1
        ipv4_measurements+=1

        state = define_state(vantage_point_state[vantage_point]['ipv6_valid'], vantage_point_state[vantage_point]['ipv6_bogus'])
        ipv6_summary[state]+=1
        ipv6_measurements+=1

        total_summary['ipv4_valid'][vantage_point_state[vantage_point]['ipv4_valid']]+=1
        total_summary['ipv4_bogus'][vantage_point_state[vantage_point]['ipv4_bogus']]+=1
        total_summary['ipv6_valid'][vantage_point_state[vantage_point]['ipv6_valid']]+=1
        total_summary['ipv6_bogus'][vantage_point_state[vantage_point]['ipv6_bogus']]+=1


    if len(ipv4_summary)>0:
        print('Trust Chain State IPv4 ({} - {})'.format(
            start_date.strftime('%Y-%m-%d %H:%M'), stop_date.strftime('%Y-%m-%d %H:%M')))
        print('Insecure:\t{} ({}%)\tSecure:\t{} ({}%)\tBogus:\t{} ({}%)\tUnknown:\t{} ({}%)'.format(
                ipv4_summary['insecure'], round(ipv4_summary['insecure']/ipv4_measurements*100,2),
                ipv4_summary['secure'], round(ipv4_summary['secure']/ipv4_measurements*100,2),
                ipv4_summary['bogus'], round(ipv4_summary['bogus']/ipv4_measurements*100,2),
                ipv4_summary['unknown'], round(ipv4_summary['unknown']/ipv4_measurements*100,2)))

    if len(ipv6_summary)>0:
        print('Trust Chain State IPv6 ({} - {})'.format(
            start_date.strftime('%Y-%m-%d %H:%M'), stop_date.strftime('%Y-%m-%d %H:%M')))
        print('Insecure:\t{} ({}%)\tSecure:\t{} ({}%)\tBogus:\t{} ({}%)\tUnknown:\t{} ({}%)'.format(
                ipv6_summary['insecure'], round(ipv6_summary['insecure']/ipv6_measurements*100,2),
                ipv6_summary['secure'], round(ipv6_summary['secure']/ipv6_measurements*100,2),
                ipv6_summary['bogus'], round(ipv6_summary['bogus']/ipv6_measurements*100,2),
                ipv6_summary['unknown'], round(ipv6_summary['unknown']/ipv6_measurements*100,2)))




def define_state(state_valid, state_bogus):
    """Returns the state of a VP
    for the trust-chain measurements."""

    if state_valid is None or state_bogus is None:
        return 'unknown'
    elif state_valid == 'NOERROR' and state_bogus == 'NOERROR':
        return 'insecure'
    elif state_valid == 'NOERROR' and state_bogus == 'SERVFAIL':
        return 'secure'
    else:
        return 'bogus'


def get_details(time_series, attributes):
    """Returns the results as a time series."""

    if len(time_series) == 0:
        return

    df = pd.DataFrame(time_series, columns = ['created', 'target', 'state'])

    freq = '0S'
    if attributes[0] == 'pubdelay':
        freq = str(config['MEASUREMENTS']['msm_frequency_publication_delay'])+'S'      
    else:
        freq = str(config['TTLS']['ttl_'+attributes[1]])+'S'  

    df = df.groupby(pd.Grouper(key='created', freq=freq)).apply(lambda x: x.groupby(['target', 'state']).count())
    df = df.unstack().fillna(0)
    df = df.apply(lambda x: x/x.sum()*100, axis=1)
    df = df.stack()
    df = df.unstack(level=1)
    df = df['created'].unstack().fillna(0)

    print(df)

    return
