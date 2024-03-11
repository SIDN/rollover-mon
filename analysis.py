import logging
from collections import defaultdict
import datetime as dt
import json
from matplotlib import pyplot as plt
import pandas as pd
import database
from misc.config import config


def get_state(msm_results, monitoring_target, details=True, figure=True, groundtruth=False):
    df = pd.DataFrame(msm_results,
                      columns=['msm_id', 'monitoring_goal', 'query_type', 'target', 'ts', 'vp', 'vals'])

    df['ts_dt'] = df['ts'].apply(lambda x: dt.datetime.fromtimestamp(x, dt.UTC))
    df = pd.merge(df,
                  df['vals'].apply(lambda x: pd.Series(index=json.loads(x).keys(), data=json.loads(x).values())),
                  left_index=True, right_index=True)

    if monitoring_target == 'propdelay':
        analyze_propdelay(df, details, figure)

    elif monitoring_target == 'pubdelay':
        analyze_pubdelay(df, details, figure)

    elif monitoring_target == 'trustchain':
        analyze_trustchain(df, details, figure, groundtruth)


def analyze_propdelay(df, details, figure):
    record = 'DNSKEY'

    if 'flags' not in df.columns:
        df['flags'] = 'DS'
        record = 'DS'

    df_state = (df
                .set_index('ts_dt')
                .groupby(pd.Grouper(freq=config['TTLS'][f'ttl_{df["query_type"].iloc[0]}'] + 's'))
                .apply(lambda x: x.groupby(['target', 'flags', 'key_tag'])['vp'].nunique())
                )

    df_state_sum = (df
                    .set_index('ts_dt')
                    .groupby(pd.Grouper(freq=config['TTLS'][f'ttl_{df["query_type"].iloc[0]}'] + 's'))
                    .apply(lambda x: x.groupby(['target', 'flags'])['vp'].nunique())
                    )

    if figure:
        plot_propdelay(df_state, record)

    if details:
        print(get_json_pubdelay_propdelay(df_state, df_state_sum))


def analyze_pubdelay(df, details, figure):
    record = 'DNSKEY'

    if 'flags' not in df.columns:
        df['flags'] = 'DS'
        record = 'DS'

    df_state = (df
                .set_index('ts_dt')
                .groupby(pd.Grouper(freq=config['MEASUREMENTS'][f'msm_frequency_publication_delay'] + 's'))
                .apply(lambda x: x.groupby(['target', 'flags', 'key_tag'])['vp'].nunique())
                )

    df_state_sum = (df
                    .set_index('ts_dt')
                    .groupby(pd.Grouper(freq=config['MEASUREMENTS'][f'msm_frequency_publication_delay'] + 's'))
                    .apply(lambda x: x.groupby(['target', 'flags'])['vp'].nunique())
                    )
    if figure:
        plot_pubdelay(df_state, record)

    if details:
        print(get_json_pubdelay_propdelay(df_state, df_state_sum))


def analyze_trustchain(df, details, figure, groundtruth=False):

    df_state = (df
                .set_index('ts_dt')
                .groupby(pd.Grouper(freq=str(int(config['TTLS']['ttl_dnskey'])*2) + 's'))
                .apply(lambda x: x.groupby(['target', 'vp', 'return_code', 'query_type'])['ts'].count())
                .unstack()
                .unstack()
                .fillna(0)
                )

    if df_state.shape[1] == 1:
        print(df_state.head())
        logging.warning('Not enough trustchain mesurements. Abort')
        return

    idx_secure = ((df_state['bogus']['NOERROR'] == 0)
                  & (df_state['bogus']['SERVFAIL'] > 0)
                  & (df_state['valid']['NOERROR'] > 0)
                  & (df_state['valid']['SERVFAIL'] == 0)
                  )

    idx_insecure = ((df_state['bogus']['NOERROR'] > 0)
                    & (df_state['bogus']['SERVFAIL'] == 0)
                    & (df_state['valid']['NOERROR'] > 0)
                    & (df_state['valid']['SERVFAIL'] == 0)
                    )

    idx_bogus = ((df_state['bogus']['NOERROR'] == 0)
                 & (df_state['bogus']['SERVFAIL'] > 0)
                 & (df_state['valid']['NOERROR'] == 0)
                 & (df_state['valid']['SERVFAIL'] > 0)
                 )
    if groundtruth:
        bogus_and_inconsistent_vps = (df_state[idx_bogus | (~idx_secure & ~idx_insecure & ~idx_bogus)]
                                      .reset_index()['vp']
                                      .drop_duplicates()
                                      .tolist())

        database.store_excluded_vps(bogus_and_inconsistent_vps)
        print('Bogus and inconsistent VPS stored in VP. Measurements by these VPs will be ignored from now on.')

        return

    df_secure = (df_state[idx_secure]
                 .reset_index()
                 .groupby(['ts_dt', 'target'])['vp']
                 .nunique()
                 .unstack())

    df_insecure = (df_state[idx_insecure]
                   .reset_index()
                   .groupby(['ts_dt', 'target'])['vp']
                   .nunique()
                   .unstack())

    df_bogus = (df_state[idx_bogus]
                .reset_index()
                .groupby(['ts_dt', 'target'])['vp']
                .nunique()
                .unstack())

    df_state_v4 = pd.DataFrame(index=df_state.index.levels[0],
                               columns=['secure', 'insecure', 'bogus'])

    if '4' in df_secure:
        df_state_v4['secure'] = df_secure['4']
    if '4' in df_insecure.columns:
        df_state_v4['insecure'] = df_insecure['4']
    if '4' in df_bogus.columns:
        df_state_v4['bogus'] = df_bogus['4']

    df_state_v6 = pd.DataFrame(index=df_state.index.levels[0],
                               columns=['secure', 'insecure', 'bogus'])

    if '6' in df_secure.columns:
        df_state_v6['secure'] = df_secure['6']
    if '6' in df_insecure.columns:
        df_state_v6['insecure'] = df_insecure['6']
    if '6' in df_bogus.columns:
        df_state_v6['bogus'] = df_bogus['6']

    df_state_v4 = df_state_v4.fillna(0)
    df_state_v6 = df_state_v6.fillna(0)



    if details:
        print(get_json_trustchain(df_state_v4, df_state_v6))

    if figure:
        plot_trustchain(df_state_v4, df_state_v6)


def get_json_pubdelay_propdelay(df_state, df_state_sum):
    msm_json = defaultdict(lambda: defaultdict(
        lambda: defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(
                    lambda: defaultdict(float)
                )))))

    for target in df_state.columns.levels[0].tolist():
        for keytype in [256, 257, 'DS']:
            if keytype in df_state[target].columns.levels[0]:
                for keytag in df_state[target][keytype].columns:
                    for ts_dt, vps in df_state[target][keytype][keytag].items():
                        msm_json[int(ts_dt.timestamp())][target][keytype][keytag]['probes'] = vps

                        share = vps / df_state_sum.loc[ts_dt][target][keytype] * 100
                        msm_json[int(ts_dt.timestamp())][target][keytype][keytag]['share'] = round(share, 2)

    return json.dumps(msm_json)


def get_json_trustchain(df_state_v4, df_state_v6):
    msm_json = defaultdict(lambda: defaultdict(
        lambda: defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(float)
            ))))

    for ts_dt in df_state_v4.index:
        for ipv in ["4", "6"]:
            for state in ["secure", "insecure", "bogus"]:
                vps = 0
                all_vps = 0
                if ipv == "4":
                    vps = df_state_v4.loc[ts_dt, state]
                    all_vps = df_state_v4.loc[ts_dt].sum()
                elif ipv == "6":
                    vps = df_state_v6.loc[ts_dt, state]
                    all_vps = df_state_v6.loc[ts_dt].sum()

                msm_json[int(ts_dt.timestamp())][ipv][state]['probes'] = int(vps)
                share = vps / all_vps * 100
                msm_json[int(ts_dt.timestamp())][ipv][state]['share'] = round(share, 2)

    return json.dumps(msm_json)


def plot_pubdelay(df_state, record):

    ips_dict = get_ip_to_domain_name_dict()
    nameservers = (df_state.columns.levels[0].tolist())

    if record == 'DS':
        keytypes = ['DS']
    else:
        keytypes = [256, 257]

    for key_type in keytypes:
        fig, ax = plt.subplots()

        for nameserver in nameservers:
            if key_type in df_state[nameserver].columns.levels[0].tolist():
                df_zsk_ksk = df_state[nameserver][key_type]
                df_zsk_ksk = df_zsk_ksk.divide(df_zsk_ksk.sum(1), axis=0) * 100
                for key_tag in df_zsk_ksk.columns:
                    ax.plot(df_zsk_ksk[key_tag], label=f'{ips_dict[nameserver]} ({nameserver}): {key_tag}', marker='o')

        key_type_txt = ''
        if key_type == 256:
            key_type_txt = 'ZSK'
            ax.set_title(f"ZSKs seen at name servers")
        elif key_type == 257:
            key_type_txt = 'KSK'
            ax.set_title(f"KSKs seen at name servers")
        elif key_type == 'DS':
            key_type_txt = 'DS'
            ax.set_title(f"DS seen at name servers")

        ax.legend()
        ax.set_ylim(0, 105)
        ax.set_ylabel('Seen by probes (%)')

        fig.tight_layout()
        fig.autofmt_xdate()
        fig.savefig(f'./{config["OUTPUT"]["figures"]}/pubdelay_{key_type_txt}.png')


def plot_propdelay(df_state, record):
    ipvs = (df_state.columns.levels[0].tolist())

    if record == 'DS':
        keytypes = ['DS']
    else:
        keytypes = [256, 257]

    for key_type in keytypes:
        fig, ax = plt.subplots()

        for ipv in ipvs:
            if key_type in df_state[ipv].columns.levels[0].tolist():
                df_zsk_ksk = df_state[ipv][key_type]
                df_zsk_ksk = df_zsk_ksk.divide(df_zsk_ksk.sum(1), axis=0) * 100
                for key_tag in df_zsk_ksk.columns:
                    linestyle = '-'
                    if ipv == '4':
                        linestyle = '--'
                    ax.plot(df_zsk_ksk[key_tag], label=f'IPv{ipv}: {key_tag}', marker='o', linestyle=linestyle)

        key_type_txt = ''
        if key_type == 256:
            key_type_txt = 'ZSK'
            ax.set_title(f"ZSKs seen at resolvers")
        elif key_type == 257:
            key_type_txt = 'KSK'
            ax.set_title(f"KSKs seen at resolvers")
        elif key_type == 'DS':
            key_type_txt = 'DS'
            ax.set_title(f"DS seen at resolvers")

        ax.legend()
        ax.set_ylim(0, 105)
        ax.set_ylabel('Seen by probes (%)')

        fig.tight_layout()
        fig.autofmt_xdate()
        fig.savefig(f'./{config["OUTPUT"]["figures"]}/propdelay_{key_type_txt}.png')


def plot_trustchain(df_state_v4, df_state_v6):
    state_style = {'secure': ['green', '-', 'o'],
                   'insecure': ['orange', '--', 's'],
                   'bogus': ['red', '-.', 'x']}

    for df_state, ipv in [[df_state_v4, 4], [df_state_v6, 6]]:
        fig, ax = plt.subplots()

        df_state = df_state.divide(df_state.sum(1), axis=0) * 100

        for state in df_state.columns:
            ax.plot(df_state[state], label=state, color=state_style[state][0], linestyle=state_style[state][1],
                    marker=state_style[state][2])

        ax.legend()
        ax.set_ylim(0, 105)
        ax.set_ylabel('VPs (%)')
        ax.set_title(f'State of resolvers (IPv{ipv})')

        fig.tight_layout()
        fig.autofmt_xdate()
        fig.savefig(f'./{config["OUTPUT"]["figures"]}/trustchain_{ipv}.png')


def get_ip_to_domain_name_dict():
    ips_dict = {}
    for relationship in ['CHILDREN', 'PARENTS']:
        for ns in config[relationship]:
            for ip in config[relationship][ns].split():
                ips_dict[ip.strip().replace(',', '')] = ns

    return ips_dict
