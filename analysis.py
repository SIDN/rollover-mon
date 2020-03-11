from collections import defaultdict 
from datetime import timedelta
#from matplotlib import pyplot as plt

from ripe.atlas.sagan import DnsResult
import pandas as pd

from misc.tools import calc_keyid, plot_timeseries, plot_timeseries_pubdelay, plot_timeseries_propdelay
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

        
        if not details:
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

            if not details:
                print('Key Tag\t# Observed (Share %)')
                for key in keys_zsk.keys():
                    print('{}\t\t{} ({}%)'.format(key, keys_zsk[key], round(keys_zsk[key]/responses_counter_zsk*100,2)))

                for key in keys_ksk.keys():
                    print('{}\t\t{} ({}%)'.format(key, keys_ksk[key], round(keys_ksk[key]/responses_counter_ksk*100,2)))


    if details:
        get_details(time_series, attributes, attributes[0])
 


def get_state_trust_chain(msm_results, msm_attributes, start_date, stop_date, details):
    """Processes the measurement results from RIPE Atlas
    for the trust chain.
    Prints the results as a string.
    """

    vantage_point_state = []


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

                        # if vantage_point_id not in vantage_point_state:
                        #     vantage_point_state[vantage_point_id] = []

                        return_code = response.abuf.header.return_code


                        if attributes[1] == 'valid':

                            if attributes[2] == '4':
                                vantage_point_state.append([vantage_point_id, 'ipv4', 'valid', return_code, created])

                            else:
                                vantage_point_state.append([vantage_point_id, 'ipv6', 'valid', return_code, created])

                        else:

                            if attributes[2] == '4':
                                vantage_point_state.append([vantage_point_id, 'ipv4' , 'bogus', return_code, created])
                            else:
                                vantage_point_state.append([vantage_point_id, 'ipv6', 'bogus', return_code, created])


   
    df_vantage_point_states = pd.DataFrame(vantage_point_state, 
                                            columns = ['vantage_point_id', 'ipv', 'msm', 'return_code', 'created'])
    df_vantage_point_states = df_vantage_point_states.sort_values(['vantage_point_id', 'ipv', 'created'])



    time_series_states = df_vantage_point_states.groupby(['vantage_point_id', 'ipv']).apply(lambda time_series: get_vp_state(time_series))



    time_series_states = time_series_states.reset_index()
    
    if 'ipv' not in time_series_states.columns:
        print('Measurement not started yet or no results available')
        return

    time_series_states_v4 = time_series_states[time_series_states.ipv=='ipv4']
    time_series_states_v6 = time_series_states[time_series_states.ipv=='ipv6']

   

    ipv4_time_series = [[], []]
    ipv6_time_series = [[], []]

    for vp, ts in time_series_states_v4.iterrows():
        ipv4_time_series[0]+=ts[0][0]
        ipv4_time_series[1]+=ts[0][1]

    for vp, ts in time_series_states_v6.iterrows():
        ipv6_time_series[0]+=ts[0][0]
        ipv6_time_series[1]+=ts[0][1]

    # print(ipv4_time_series)
    # ipv4_time_series = pd.DataFrame(ipv4_time_series, columns = ['created', 'state'])

    ipv4_time_series = pd.DataFrame(ipv4_time_series).transpose()
    ipv4_time_series.columns = ['created', 'state']
    ipv4_time_series = ipv4_time_series.sort_values(['created'])
    ipv4_time_series['counter'] = 1

    ipv4_time_series = ipv4_time_series.groupby([pd.Grouper(key='created', freq=str(config['TTLS']['ttl_dnskey'])+'S'), 'state']
        ).count().unstack().fillna(0)['counter']
 


    ipv6_time_series = pd.DataFrame(ipv6_time_series).transpose()
    ipv6_time_series.columns = ['created', 'state']
    ipv6_time_series = ipv6_time_series.sort_values(['created'])
    ipv6_time_series['counter'] = 1

    ipv6_time_series = ipv6_time_series.groupby([pd.Grouper(key='created', freq=str(config['TTLS']['ttl_dnskey'])+'S'), 'state']
        ).count().unstack().fillna(0)['counter']
 
    if details:
        print('Store time series to CSV and create graph')
        try:
            ipv4_time_series.to_csv(config['OUTPUT']['csv_path']+'/ip_v4_timeseries.csv')
            ipv6_time_series.to_csv(config['OUTPUT']['csv_path']+'/ip_v6_timeseries.csv')
        except Exception as e:
            print('Unable to save CSV')
            print(e)


        try:
            plot_timeseries(ipv4_time_series, 'IPv4', config['OUTPUT']['plot_path'])
            plot_timeseries(ipv4_time_series, 'IPv6', config['OUTPUT']['plot_path'])
        except Exception as e:
            print('Unable to plot and save graph')
            print(e)
    else:
        if len(ipv4_time_series)>0:
            tot = ipv4_time_series.sum().sum()
            
            insecure = 0
            if 'insecure' in ipv4_time_series.columns:
                insecure = ipv4_time_series['insecure'].sum()

            secure = 0
            if 'secure' in ipv4_time_series.columns:
                secure = ipv4_time_series['secure'].sum()

            bogus = 0
            if 'bogus' in ipv4_time_series.columns:
                insecure = ipv4_time_series['bogus'].sum()

            unknown = 0
            if 'unknown' in ipv4_time_series.columns:
                unknown = ipv4_time_series['unknown'].sum()
  

            print('Trust Chain State IPv4 ({} - {})'.format(
                  start_date.strftime('%Y-%m-%d %H:%M'),
                  stop_date.strftime('%Y-%m-%d %H:%M')))
            print('Insecure: {} ({}%)\tSecure: {} ({}%)\tBogus: {} ({}%)\tUnkown: {} ({}%)'.format(
                int(insecure),
                round(insecure/tot*100,2),
                secure,
                round(secure/tot*100,2),
                bogus,
                round(bogus/tot*100,2),
                unknown,
                round(unknown/tot*100,2)))

        if len(ipv6_time_series)>0:
            tot = ipv6_time_series.sum().sum()
            
            insecure = 0
            if 'insecure' in ipv6_time_series.columns:
                insecure = ipv6_time_series['insecure'].sum()

            secure = 0
            if 'secure' in ipv6_time_series.columns:
                secure = ipv6_time_series['secure'].sum()

            bogus = 0
            if 'bogus' in ipv6_time_series.columns:
                insecure = ipv6_time_series['bogus'].sum()

            unknown = 0
            if 'unknown' in ipv6_time_series.columns:
                unknown = ipv6_time_series['unknown'].sum()


            print('Trust Chain State IPv6 ({} - {})'.format(
                  start_date.strftime('%Y-%m-%d %H:%M'),
                  stop_date.strftime('%Y-%m-%d %H:%M')))
            print('Insecure: {} ({}%)\tSecure: {} ({}%)\tBogus: {} ({}%)\tUnkown: {} ({}%)'.format(
                insecure,
                round(insecure/tot*100,2),
                secure,
                round(secure/tot*100,2),
                bogus,
                round(bogus/tot*100,2),
                unknown,
                round(unknown/tot*100,2)))


def get_vp_state(time_series):

    # Within which time frame should the bogus and secure measurements results be combined
    combination_time_frame_s = int(config['TTLS']['ttl_dnskey'])*2

    time_series_valid = time_series[time_series.msm == 'valid']

    time_series_state = [[], []]

    for i, vals in time_series_valid.iterrows():
        time_series_bogus = time_series[ (time_series.msm == 'bogus') 
                                        & ((time_series.created>=vals.created - timedelta(seconds=combination_time_frame_s))
                                         | (time_series.created<=vals.created + timedelta(seconds=combination_time_frame_s))) ]
        # print(time_series_bogus)

        if len(time_series_bogus) > 0:
            state = define_state(vals.return_code, time_series_bogus.iloc[-1].return_code)
            # print(state)
        else:
            state  = 'unknown'
        
        time_series_state[0].append(vals.created)
        time_series_state[1].append(state)

    # print(time_series_state)
    return time_series_state



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


def get_details(time_series, attributes, msm_type):
    """
    Returns the results as a time series,
    stores it as a CSV and plots it as PDF
    """

    if len(time_series) == 0:
        return

    df = pd.DataFrame(time_series, columns = ['created', 'target', 'state'])

    freq = '0S'
    if attributes[0] == 'pubdelay':
        freq = str(config['MEASUREMENTS']['msm_frequency_publication_delay'])+'S'      
    else:
        freq = str(config['TTLS']['ttl_'+attributes[1]])+'S'  

    df = df.groupby(pd.Grouper(key='created', freq=freq)).apply(lambda x: x.groupby(['target', 'state']).count())
    df = df['created']
    df = df.unstack().fillna(0)


    cols = [int(col) for col in df.columns.tolist()]
    if config['ROLLOVER']['key_tag_new'] == '':
        key_tag_new = -1
    else:
        key_tag_new = int(config['ROLLOVER']['key_tag_new'])
    
    key_tag_old = int(config['ROLLOVER']['key_tag_old'])


    if not (key_tag_new in cols):
        df[key_tag_new] = 0
    if not (key_tag_old in cols):
        df[key_tag_old] = 0

    df = df[[key_tag_old, key_tag_new]]
    df = df.apply(lambda x: x/x.sum()*100, axis=1)

    if key_tag_new == -1:
        df = df.drop(key_tag_new, axis=1)
    
    df = df.stack()

    if msm_type == 'propdelay':
        df = df.unstack(level=1)['4'].unstack()
        
        plot_timeseries_propdelay(df, msm_type, config['OUTPUT']['plot_path'])

    else:
        df = df.unstack(level=1).unstack()

        if key_tag_new == -1:
            plot_timeseries_pubdelay(df, msm_type, config['OUTPUT']['plot_path'], key_tag_old)
        else:
            plot_timeseries_pubdelay(df, msm_type, config['OUTPUT']['plot_path'], key_tag_new)


    df.reset_index().to_csv(config['OUTPUT']['csv_path']+'/'+msm_type+'_timeseries.csv',
                             index=False, )

    return
