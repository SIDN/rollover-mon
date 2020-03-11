import struct
import base64
from matplotlib import pyplot as plt

def calc_keyid(flags, protocol, algorithm, dnskey):
    """Returns the DNSKEY key ID."""

    st = struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
    st += base64.b64decode(dnskey)

    cnt = 0
    for idx in range(len(st)):
        s = struct.unpack('B', st[idx:idx+1])[0]
        if (idx % 2) == 0:
            cnt += s << 8
        else:
            cnt += s

    return ((cnt & 0xFFFF) + (cnt >> 16)) & 0xFFFF


def plot_timeseries(timeseries, title, path):
    color_dict = {'secure': 'green',
                    'insecure': 'yellow',
                    'bogus': 'red',
                    'unkown': 'grey'
                    }

    timeseries = timeseries.iloc[:-1]
    timeseries = timeseries.div(timeseries.sum(1), axis=0)*100

    fig, ax = plt.subplots()

    for column in timeseries:
        ax.plot(timeseries[column], label=column, color = color_dict[column])

    ax.set_ylabel('Vantage Points (%)')
    ax.set_xlabel('Date')
    ax.set_ylim(0, 100)
    ax.set_title('Resolvers treating the Zone as Secure, Insecure or Bogus')

    ax.legend()
    fig.autofmt_xdate()
    fig.savefig(path+'/'+title+'_trustchain.pdf')


def plot_timeseries_propdelay(timeseries, title, path):

    fig, ax = plt.subplots()

    for column in timeseries:
        ax.plot(timeseries[column], label=column)

    ax.set_ylabel('Vantage Points (%)')
    ax.set_xlabel('Date')
    ax.set_ylim(0)
    ax.set_title('Propagation Delay')

    ax.legend()
    fig.autofmt_xdate()
    fig.savefig(path+'/'+title+'.pdf')


def plot_timeseries_pubdelay(timeseries, title, path, key_tag):

    fig, ax = plt.subplots()

    for server_key in timeseries:
        if server_key[1] == key_tag:
            ax.plot(timeseries[server_key], label=server_key[0])

    ax.set_ylabel('Vantage Points (%)')
    ax.set_xlabel('Date')
    ax.set_ylim(0)
    ax.set_title(f'Publication Delay for Key {key_tag}')

    ax.legend()
    fig.autofmt_xdate()
    fig.savefig(path+'/'+title+'.pdf')