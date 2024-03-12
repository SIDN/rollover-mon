# Rollover Mon README


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
You can find a more academic description and methodology [here](https://ris.utwente.nl/ws/portalfiles/portal/169276088/08712408.pdf).

You can find more information about DNSSEC rollovers [here](https://tools.ietf.org/html/rfc6781) and about the timing of rollovers [here](https://tools.ietf.org/html/rfc7583).


## Installation

### Requirements

You need to install the following python libraries:

```
pandas
matplotlib
ripe.atlas.sagan
ripe.atlas.cousteau
```

### Steps

#### 1: Edit configuration

The file 'config.ini; contains parameters that are necessary to set up the
tool and the measurements. First, go through every parameter and define the
parameters accordingly. The config file explains the parameters in more
detail.

You also need to create a directory called `figs`. This is where the figures will be stored.

#### 2. Initiate database

Create an empty file where the database should be located. This should be the same file as defined in the config file.

Execute 'init_db.py' to initiate the database. This script will create the
necessary table in the SQLite DB.

After this step. You're good to go.

## Usage

### Initiate measurements

To monitor a rollover, the measurements should be
started **before** the beginning of a stage (that is, before a new key, signature
or DS record is replaced).

Operators can initiate three different types of measurements:

- measurements to monitor the deployment and withdrawal of the records directly at the name servers (publication delay)
- measurements to monitor the deployment and withdrawal of the records from indirectly from the perspective of recursive resolvers of RIPE Atlas probes (propagation delay)
- measurements to monitor the trust chain

#### Monitor publication delay

The command to start measurements of the publication delay is as follows:

```
python rollover_mon.py pubdelay --record [dnskey|ds] --start
```

Depending on which record is added or withdrawn, the operator has to define which record the measurements 
should monitor with the help of the '--record' parameter.

If you select 'dnskey', then the measurements will query the name
servers of the zone of which the keys are rolled. If 'ds' is selected, then
the name servers of the parent zone are queried.


#### Monitor propagation delay

The command to start measurements of the propagation delay is as follows:

```
python rollover_mon.py propdelay --record [dnskey|ds] --start
```

Depending on which record is added or withdrawn, the operator has to define
which record the measurements should monitor with the help of the '--record'
parameter.

We can schedule measurements using the '--start-date' and '--stop-date' parameters, e.g.:

```
python rollover_mon.py propdelay --record [dnskey|rrsig|ds] --start --start-date "2023-06-05 14:00" --stop-date "2023-06-05 20:00"
```

If we omit the '--stop-date' parameter, the measurement runs forever and
needs to be stopped with the '--stop' parameter (see below).


#### Monitor trust chain

The command to start measurements of the trust chain is as follows:

```
python rollover_mon.py trustchain  --start
```

Note, that we do not have to set the '--record' parameter.

Also, the measurements for the trust chain can be scheduled with '--start-date'
and '--stop-date'.

Note: Depending on the measurement frequency, which depends on the TTL of your DNSKEY, you might need to wait up to 
two times the TTL before you will be able to get an output.


### Stop measurements

Stopping the measurements works similar to starting the measurements, but
instead of adding the '--start' argument we need to add the '--stop' argument.

```
# Publication Delay
python rollover_mon.py pubdelay --record [dnskey|ds] --stop

# Propagation Delay
python rollover_mon.py propdelay --record [dnskey|ds] --stop

# Trust Chain
python rollover_mon.py trustchain  --stop
```

### Get rollover state

To get the state of the rollover, the following command is used:

```
# Publication Delay
python rollover_mon.py pubdelay --record [dnskey|ds] --state

# Propagation Delay
python rollover_mon.py propdelay --record [dnskey|ds] --state

# Trust Chain
python rollover_mon.py trustchain  --state
```



By default, the measurements of the last two hours are analyzed.

By defining the parameters '--start-date' and '--stop-date' we can define from
which time frame we want to analyze the measurements, e.g.:

```
# Publication Delay
python rollover_mon.py pubdelay --record [dnskey|rrsig|ds] --state --start-date "2018-06-05 14:00" --stop-date "2018-06-05 20:00"
```

If we omit the parameter '--stop-date' then every measurement from '--start-date' until now are analyzed.

Every time we collect the "state", the software checks if it has the recent measurement results stored in the local
database and fetches the missing measurement results. Depending on when we've executed this command last, collecting
the recent measurements might take a while.


## Output

**Figure** 

Commands with the `--state` argument will create a new figure, located in the directory configured in the configuration file.
The figures show which keys and DS records are published where, how far the records have propagated, and to what extent 
resolvers can validate the zone.

**JSON**

With the option '--json', the software generates a JSON objects of the measurement results and prints it on the 
command line.

## Remove noise

Internet measurements can be noisy, and measurements performed with RIPE Atlas are no exception. Some recursive resolvers,
used by RIPE Atlas probes might always fail to validate your zone. For this reason, you might want to ignore measurements 
from these probes.

To do so, start your `trustchain` measurement and let it run for at least twice the TTL of your DNSKEY records. Then, run:

```
python rollover_mon.py groundtruth
```

This command will collect all RIPE Atlas vantage points (probe-resolver-pair) and add those to the "excluded_vps" table
in your local database that already cannot validate your zone or that report other inconsistent results.

From now on, the software will ignore measurements results from those vantage points when you run it with the `--state`
option. 


Note: The software will continue collect measurements from these vantage points and store them in the 
"measurement_data" table. 

Note: Only run this command when you are sure that your zone is working fine.  

Tip: You can always connect to the local DB directly and add or remove VPs from "excluded_vps".


