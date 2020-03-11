# Rollover Mon (Beta) README

## Latest Change (2020-03-11)

- For the option _pubdelay_ and _propdelay_ the behavior of the _--details_ parameter has changed. It now saves a time series of the resolver state as a CSV and plots the timeseries as a PDF.
- _config.ini_ has 2 new parameters to define, what the key tag of the current key is and what the key tag of the new tag is. The latter can be left blank if still unknown.

## Latest Change (2020-03-10)

- For the option _trustchain_ the behavior of the _--details_ parameter has changed. It now saves a time series of the resolver state as a CSV and plots the timeseries as a PDF.
- Plotting requires matplotlib library
- _config.ini_ has 2 new parameters to define where to store the CSV and PDF


## Introduction 

Rollover Mon initiates and analyzes measurements to monitor DNSSEC rollovers.
It gives operators of signed zones insights into:

- the state of the deployment of their new signatures and keys and the withdrawal of old ones
	- at the authoritative name servers 
	- at recursive resolvers of their clients
- the state of the trust chain

Thereby, operators can make sure that 
- their keys are deployed correctly at the authoritative name servers
- their keys are picked up by recursive resolvers
- their zone stays secure throughout the whole rollover

You can find more information about the underlying measurement methodology [here](https://www.sidnlabs.nl/a/weblog/keep-m-rolling-monitoring-ses-dnssec-algorithm-rollover?language_id=2&langcheck=true) or in this [talk](https://ripe76.ripe.net/archives/video/41/).
A scientific article is currently under review.

You can find more information about DNSSEC rollovers [here](https://tools.ietf.org/html/rfc6781) and about the timing of rollovers [here](https://tools.ietf.org/html/rfc7583).


## Installation

### Requirements

- \>= Python 3
- PIP
- Write access to a (local) SQLite DB

### Steps

#### 1: Edit configuration

The file 'config.ini; contains parameters that are necessary to set up the
tool and the measurements. First, go through every parameter and define the
parameters accordingly. The config file explains the parameters in more
detail.

#### 2: Install necessary python package

Use the command

```
pip install -r requirements.txt
```

to install the necessary packages in your python environment.

#### 3. Initiate Database

Execute 'init_db.py' to initiate the database. This script will create the
necessary table in the SQLite DB.

After this step. You're good to go.

## Usage

### Initiate Measurements

To thoroughly monitor a stage of the rollover, the measurements should be
started **before** the beginning of a stage (that is, before a new key, signature
or DS record is replaced).

Operators can initiate three different types of measurements:

- measurements to monitor the deployment and withdrawal of the records directly at the name servers (publication delay)
- measurements to monitor the deployment and withdrawal of the records from indirectly from the perspective of recursive resolvers of RIPE Atlas probes (propagation delay)
- measurements to monitor the trust chain

#### Monitor Publication Delay

The command to start measurements of the publication delay is as follows:

```
python rollover_mon.py pubdelay --record [dnskey|rrsig|ds] --start
```

Depending on which record is added or withdrawn, the operator has to define which record the measurements should monitor with the help of the '--record' parameter.

If 'dnskey' or 'rrsig' is selected, then the measurements will query the name
servers of the zone of which the keys are rolled. If 'ds' is selected, then
the name servers of the parent zone are queried.


#### Monitor Propagation Delay

The command to start measurements of the propagation delay is as follows:

```
python rollover_mon.py propdelay --record [dnskey|rrsig|ds] --start
```

Depending on which record is added or withdrawn, the operator has to define
which record the measurements should monitor with the help of the '--record'
parameter.

We can schedule measurements using the '--start-date' and '--stop-date' parameters, e.g.:

```
python rollover_mon.py propdelay --record [dnskey|rrsig|ds] --start --start-date "2018-06-05 14:00" --stop-date "2018-06-05 20:00"
```

If we omit the '--stop-date' parameter, the measurement runs forever and
needs to be stopped with the '--stop' parameter (see below).


#### Monitor Trust Chain

The command to start measurements of the trust chain is as follows:

```
python rollover_mon.py trustchain  --start
```

Note, that we do not have to set the '--record' parameter.

Also the measurements for the trust chain can be scheduled with '--start-date'
and '--stop-date'.



### Stop Measurements

Stopping the measurements works similar to starting the measurements, but
instead of adding the '--start' argument we need to add the '--stop' argument.

```
# Publication Delay
python rollover_mon.py pubdelay --record [dnskey|rrsig|ds] --stop

# Propagation Delay
python rollover_mon.py propdelay --record [dnskey|rrsig|ds] --stop

# Trust Chain
python rollover_mon.py trustchain  --stop
```

### Get Rollover Status

To get the status of the rollover, the following command is used:

```
# Publication Delay
python rollover_mon.py pubdelay --record [dnskey|rrsig|ds] --status

# Propagation Delay
python rollover_mon.py propdelay --record [dnskey|rrsig|ds] --status

# Trust Chain
python rollover_mon.py trustchain  --status
```

By default, the measurements of the last hours are analyzed.

By defining the parameters '--start-date' and '--stop-date' we can define from
which time frame we want to analyze the measurements, e.g.:

```
# Publication Delay
python rollover_mon.py pubdelay --record [dnskey|rrsig|ds] --status --start-date "2018-06-05 14:00" --stop-date "2018-06-05 20:00"
```

If we omit the parameter '--stop-date' then every measurement from '--start-date' until now are analyzed.

### The Output


**Publication Delay:**

```
python rollover_mon.py pubdelay --record dnskey --status
Monitoring pubdelay of DNSKEY at 192.0.2.1 (2018-06-07 14:18 - 2018-06-07 15:18)
Key Tag	# Observed (Share %)
55719		4 (66.67%)
62663		2 (33.33%)
54576		2 (33.33%)
20237		4 (66.67%)
Monitoring pubdelay of DNSKEY at 192.0.2.2 (2018-06-07 14:18 - 2018-06-07 15:18)
Key Tag	# Observed (Share %)
55719		5 (45.45%)
62663		6 (54.55%)
20237		3 (100.0%)
```

As output we see, how many probes have observed which key. The share is
calculated for ZSKs and KSKs separately. The output is split for each name
server configured in the config file.

**Propagation Delay:**

```
Monitoring propdelay of DNSKEY (IPv4 (2018-06-07 14:28 - 2018-06-07 15:28))
Key Tag	# Observed (Share %)
55719		1 (100.0%)
54576		1 (50.0%)
20237		1 (50.0%)
Monitoring propdelay of DNSKEY (IPv6 (2018-06-07 14:28 - 2018-06-07 15:28))
Key Tag	# Observed (Share %)
62663		1 (50.0%)
55719		1 (50.0%)
```

As output we see, how many recursive resolvers have which key in their cache.
The share is calculated for ZSKs and KSKs separately.


**Trust Chain:**

```
python rollover_mon.py trustchain --status
Trust Chain State IPv4 (2020-03-10 08:13 - 2020-03-10 09:13)
Insecure: 153 (100.0%)	Secure: 0 (0.0%)	Bogus: 0 (0.0%)	Unkown: 0 (0.0%)
Trust Chain State IPv6 (2020-03-10 08:13 - 2020-03-10 09:13)
Insecure: 153 (100.0%)	Secure: 0 (0.0%)	Bogus: 0 (0.0%)	Unkown: 0 (0.0%)
```
As output we see, how many recursive resolvers are currently 

- Insecure: Are able to resolve the test domains without any problem but do not validate
- Secure: Are able to resolve the test domains and do DNSSEC validation
- Bogus: Are not able to resolve the test domains
- Unknown: We have not seen enough measurements for the resolver to define its status

A sudden increase in resolvers that are 'bogus' or a decrease of resolvers
that are 'secure' are signs for a failure during the rollover.


**Details**

With the option '--details', a more detailed output can be produced. 

It does not generate an output but generates a time series of the state of the measured resolvers across and stores it as a CSV.
The CSV is stored in the location defined in the _[OUTPUT]_ --> _csv_path_ parameter defined in _config.ini_.
Every time the command is run, a new CSV is created and the old one is overwritten.

Additionally, the time series is plotted as a PDF. 
The PDF is stored in the location defined in the _[OUTPUT]_ --> _plot_path_ parameter defined in _config.ini_.
Every time the command is run, a new PDF is created and the old one is overwritten.

