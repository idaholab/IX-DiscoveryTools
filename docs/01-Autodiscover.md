# Installation
The tool can be installed by running the `install.sh` script present in the root directory and following the provided prompts.

# Running The Tool
The tool can be run with the command line arugments:
```
python3 main.py -i ens33 -p.1 127.0.0.1
```
or it can be specified to use a configuration file:
```
python3 main.py --cfg config/example.conf
```


# Config Documentation

The config file has the same arguments (and default values) as the command line arguments. The format for config is YAML and therefore indentation must be consistent and is important across the file.  
example configuration files are present under `/config`

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
        - do_not_resolve_hosts
    - pcap
        - file
        - enchanced
    - cve
    - remote
        - csv
        - hardware
        - process
        - filetree
        - directory
    - openvas
        - host
        - username
        - password


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

## plugins.network.host_discovery
**Description**: Whether to use nmap's host discovery instead of assuming all hosts are up. Set to `False` if hosts will not respond to ping. Setting to `False` can greatly increase scan times when scanning a range of IPs  
**Default**: `False`  
**Example**: `True`  

## plugins.network.do_not_resolve_hosts
**Description**: Disables resolving of hosts when performing nmap scans.
**Default**: `False`  
**Example**: `True`  

## plugins.pcap.file
**Description**: Path to a pcap file to use for determining hosts that send network traffic to each other. This argument is required to enable the dataflow plugin.  
**Default**: `None`  
**Example**: `./packet_capture.pcap`  

## plugins.pcap.enchanced
**Description**: Enables the purely passive version of the dataflow plugin.
**Default**: `False`  
**Example**: `True`  

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
**Description**: Whether to run commands that gather hardware data on remote hosts.  
**Default**: `True`  
**Example**: `False`  

## plugins.remote.filetree
**Description**: Whether to run commands that gather filesystem data on remote hosts.  
**Default**: `True`  
**Example**: `False`  

## plugins.remote.directory
**Description**: The specified directory to capture a filesystem tree from.
**Default**: `/etc`  
**Example**: `/tmp`  

## plugins.openvas.host
**Description**: The host to use for the target(s) of the OpenVAS scan.
**Default**: `127.0.0.1`  
**Example**: `192.168.0.1/24`  

## plugins.openvas.username
**Description**: The username to use for the target(s) of the OpenVAS scan.
**Default**: `admin`  
**Example**: `root`

## plugins.openvas.password
**Description**: The password to use for the target(s) of the OpenVAS scan.
**Default**: `admin`  
**Example**: `toor`  
# Command Line Documentation
```
usage: main.py [-h] [-f FILE] [-d DEST] [-i INTERFACE] [-p.1 NMAP] [-p.2] [-p.3 NMAP_ARGS] [-p.4]
               [-p.5] [-p.6] [-p.7 FILE] [-p.8] [-p.9] [-p.10 CSV] [-p.11 PROCESS] [-p.12 HARDWARE]
               [-p.13 FILETREE] [-p.14 DIRECTORY] [-p.15 FILE] [-p.16 HOST] [-p.17 USERNAME]
               [-p.18 PASSWORD] [--cfg CFG] [--print_config [={comments,skip_null}+]]

IX AutoDiscover Utility.

optional arguments:
  -h, --help            Show this help message and exit.
  -f FILE, --file FILE  Path to stix file to read in 
  -d DEST, --dest DEST  Path to save stix bundle
  -i INTERFACE, --interface INTERFACE
                        interface to use for pcap (default: ens33)
  -p.1 NMAP, --plugins.network.nmap NMAP
                        CIDR network to run nmap on (default: null)
  -p.2, --plugins.network.sudo
                        run nmap as sudo, some TCP/IP fingerprinting requires this (default: False)
  -p.3 NMAP_ARGS, --plugins.network.nmap_args NMAP_ARGS
                        additional args for nmap (default: null)
  -p.4, --plugins.network.no_host_discovery
                        prevents the nmap plugin from doing host discovery (default: False)
  -p.5, --plugins.network.no_services
                        prevents the nmap plugin from adding services to output STIX (default:
                        False)
  -p.6, --plugins.network.do_not_resolve_hosts
                        prevents the nmap plugin from doing reverse DNS lookups (default: False)
  -p.7 FILE, --plugins.pcap.file FILE
                        pcap or pcapng file to ingest for pcap plugin (default: null)
  -p.8, --plugins.pcap.enhanced
                        use enhanced dataflow (default: False)
  -p.9, --plugins.cve   whether or not to run cve_search (default: False)
  -p.10 CSV, --plugins.remote.csv CSV
                        .CSV cred file for remote information gathering (default: null)
  -p.11 PROCESS, --plugins.remote.process PROCESS
                        Whether to run process gathering (default: True)
  -p.12 HARDWARE, --plugins.remote.hardware HARDWARE
                        Whether to run hardware gathering (default: True)
  -p.13 FILETREE, --plugins.remote.filetree FILETREE
                        Whether to run filetree gathering (default: True)
  -p.14 DIRECTORY, --plugins.remote.directory DIRECTORY
                        The remote directory to start the filetree plugin on (default: /etc/)
  -p.15 FILE, --plugins.openvas.file FILE
                        An OpenVAS XML file to use for input instead of scanning host(s) (default:
                        null)
  -p.16 HOST, --plugins.openvas.host HOST
                        Host for openvas (default: null)
  -p.17 USERNAME, --plugins.openvas.username USERNAME
                        Host for openvas target(s) (default: admin)
  -p.18 PASSWORD, --plugins.openvas.password PASSWORD
                        Password for openvas target(s) (default: admin)
  --cfg CFG             Config file input
  --print_config [={comments,skip_null}+]
                        Print configuration and exit.

```

