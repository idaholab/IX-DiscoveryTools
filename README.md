
## Todo
See https://d520git.inl.gov/infrastructure_expression/autodiscover/-/issues/1

## Autodiscover Planning Document
See https://d520git.inl.gov/infrastructure_expression/autodiscover/-/blob/master/Autodiscover%20Planning.docx  
Or in teams: `Idaho National Laboratory\GRP-IX-LDRD - General\Design\Autodiscover Planning.docx`

# Running The Tool
The tool can be run with the command line arugments:
```
python3 main.py -i ens33 -p.1 127.0.0.1
```
or if no arguments are specified it will draw from the config file
```
python3 main.py
```


# Config Documentation

The config file has the same arguments (and default values) as the command line arguments. The format for config is YAML and therefore indentation must be consistent and is important across the file.  
By default the config will be located at `./config/cfg.yaml`

The options are hierarchical, for example the option `plugins.network.nmap` with a value of `127.0.0.1` would represented as the below:

```
plugins:
  network:
    nmap: 127.0.0.1
```

# Current Argument Tree
Below is a tree of all the arugments that may be present in the config file. In depth descriptions follow directly after.

- file
- dest
- interface
- plugins
    - network
        - nmap
        - host_discovery
        - no_services
        - nmap_args
        - sudo
    - pcap
    - cve
    - remote
        - csv
        - hardware
        - process


**(Note: if arguments are no specified, or are commented out the default value will be used)**
## file
**Description**: Path to stix file to read in and pass to the first plugin  
**Default**: `None`  
**Example**: `stix_intput.json`  

## dest
**Description**: Path to output the STIX bundle to  
**Default**: `./temp/test.json`  
**Example**: `stix_output.json`  

## interface
**Description**: Path to output the STIX bundle to  
**Default**: `ens33`  
**Example**: `eth0`  

## plugins.network.nmap
**Description**: IP or IP range to scan  
**Default**: `127.0.0.1`  
**Example**: `192.168.0.0/24`  

## plugins.network.sudo
**Description**: Whether to run nmap with `sudo` and run OS detection  
**Default**: `False`  
**Example**: `True`  

## plugins.network.nmap_args
**Description**: Additional arguments to pass to nmap  
**Default**: `None`  
**Example**: `-T4 -p22`  

## plugins.network.host_discovery
**Description**: Whether to use nmap's host discovery instead of assuming all hosts are up. Set to `False` if hosts will not respond to ping. Setting to `False` can greatly increase scan times when scanning a range of IPs  
**Default**: `False`  
**Example**: `True`  

## plugins.network.no_services
**Description**: Disable outputting of service STIX objects to the STIX bundle  
**Default**: `False`  
**Example**: `True`  

## plugins.pcap.file
**Description**: Path to a pcap file to use for determining hosts that send network traffic to each other. This argument is required to enable the dataflow plugin.  
**Default**: `None`  
**Example**: `./packet_capture.pcap`  

## plugins.cve
**Description**: Whether autodiscover will attempt to find CVE's for a given service. When using this argument for the first time run autodiscover on a system with internet access to build the database.  
**Default**: `None`  
**Example**: `True`  

## plugins.remote.csv
**Description**: Path to a credential file that contains the proper credentials/ips/ports to run remote info commands on. This argument is required to enable the remote info plugin.  
**Default**: `None`  
**Example**: `creds.csv`  

## plugins.remote.process
**Description**: Whether to run commands that gather process data on remote hosts.  
**Default**: `True`  
**Example**: `False`  

## plugins.remote.hardware
**Description**: Whether to run commands that gather process data on remote hosts.  
**Default**: `True`  
**Example**: `False`  

# Command Line Documentation
```
usage: main.py [-h] [--print_config [skip_null]] [-f FILE] [-d DEST]  
               [-i INTERFACE] [-p.1 NMAP] [-p.2] [-p.3 NMAP_ARGS] [-p.4]  
               [-p.5] [-p.6 FILE] [-p.7] [-p.8 CSV] [-p.9 PROCESS]  
               [-p.10 HARDWARE] [--cfg CFG]  

IX AutoDiscover Utility.

default config file locations:
  ['config/cfg.yaml']

optional arguments:
  -h, --help            Show this help message and exit.
  --print_config [skip_null]
                        Print configuration and exit.
  -f FILE, --file FILE  Path to stix file to read in (type: <function
                        <locals>.extension at 0x7f33d64945f0>, default: null)
  -d DEST, --dest DEST  Path to save stix bundle (type: <function
                        <locals>.extension at 0x7f33d6494710>, default:
                        ./temp/test.json)
  -i INTERFACE, --interface INTERFACE
                        interface to use for pcap (default: ens33)
  -p.1 NMAP, --plugins.network.nmap NMAP
                        CIDR network to run nmap on (default: null)
  -p.2, --plugins.network.sudo
                        run nmap as sudo, some TCP/IP fingerprinting requires
                        this (default: False)
  -p.3 NMAP_ARGS, --plugins.network.nmap_args NMAP_ARGS
                        additional args for nmap (default: null)
  -p.4, --plugins.network.host_discovery
                        prevents the nmap plugin from adding services
                        (default: False)
  -p.5, --plugins.network.no_services
                        prevents the nmap plugin from adding services
                        (default: False)
  -p.6 FILE, --plugins.pcap.file FILE
                        file to ingest for pcap plugin (default: null)
  -p.7, --plugins.cve   whether or not to run cve_search (default: False)
  -p.8 CSV, --plugins.remote.csv CSV
                        csv cred file for remote information gathering
                        (default: null)
  -p.9 PROCESS, --plugins.remote.process PROCESS
                        Whether to run process gathering (default: True)
  -p.10 HARDWARE, --plugins.remote.hardware HARDWARE
                        Whether to run hardware gathering (default: True)
  --cfg CFG             Config file input
```

