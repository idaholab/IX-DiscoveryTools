#Copyright 2021, Battelle Energy Alliance, LLC
from jsonargparse import ArgumentParser, ActionConfigFile
from autodiscover.util.loader import stix_loader
from autodiscover.util.runner import plugin_runner
from autodiscover.plugins.nmap import nmap
from autodiscover.util.handler import Handler
import logging
import pathlib
import shutil
import os
import sys


def ext_check(expected_extension):
    """
    Check for file extension to match json for argparse in_file/out_file
    To move to json also see: https://codereview.stackexchange.com/questions/110108/using-argparse-with-parameters-defined-in-config-file
    """
    def extension(filename):
        if not filename.lower().endswith(expected_extension):
            raise ValueError()
        return filename
    return extension

if __name__ == "__main__":

    # logger = logging.getLogger()
    # logger.setLevel(logging.WARNING)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    logging.getLogger().addHandler(ch)
    # plugin_list = './config/plugin_config.txt'

    parser = ArgumentParser(description='IX AutoDiscover Utility.')
    parser.add_argument('-f', '--file', type=ext_check('.json'), help='Path to stix file to read in')
    parser.add_argument('-d', '--dest', type=ext_check('.json'), default='./temp/test.json', help='Path to save stix bundle')
    parser.add_argument('-i', '--interface', default='ens33', help='interface to use for pcap')
    # parser.add_argument('--disable_handler', action='store_true', help='Disable the pcap and intermediary file handler')
    parser.add_argument('-p.1', '--plugins.network.nmap', default=None, help='CIDR network to run nmap on')
    parser.add_argument('-p.2', '--plugins.network.sudo', action='store_true', default=False, help='run nmap as sudo, some TCP/IP fingerprinting requires this')
    parser.add_argument('-p.3', '--plugins.network.nmap_args', default=None, help='additional args for nmap')
    parser.add_argument('-p.4', '--plugins.network.no_host_discovery', action='store_false', default=False, help='prevents the nmap plugin from doing host discovery')
    parser.add_argument('-p.5', '--plugins.network.no_services', action='store_true', default=False, help='prevents the nmap plugin from adding services to output STIX')
    parser.add_argument('-p.6', '--plugins.network.do_not_resolve_hosts', action='store_true', default=False, help='prevents the nmap plugin from doing reverse DNS lookups')
    parser.add_argument('-p.7', '--plugins.pcap.file',  help='pcap or pcapng file to ingest for pcap plugin')
    parser.add_argument('-p.8', '--plugins.pcap.enhanced', action='store_true', default=False, help='use enhanced dataflow')
    parser.add_argument('-p.9', '--plugins.cve', action='store_true', help='whether or not to run cve_search')
    parser.add_argument('-p.10', '--plugins.remote.csv', help='.CSV cred file for remote information gathering')
    parser.add_argument('-p.11', '--plugins.remote.process', default=True, help='Whether to run process gathering')
    parser.add_argument('-p.12', '--plugins.remote.hardware', default=True, help='Whether to run hardware gathering')
    parser.add_argument('-p.13', '--plugins.remote.filetree', default=True, help='Whether to run filetree gathering')
    parser.add_argument('-p.14', '--plugins.remote.directory', default='/etc/', help='The remote directory to start the filetree plugin on')
    parser.add_argument('-p.15', '--plugins.openvas.file', default=None, help='An OpenVAS XML file to use for input instead of scanning host(s)')
    parser.add_argument('-p.16', '--plugins.openvas.host', help='Host for openvas')
    parser.add_argument('-p.17', '--plugins.openvas.username', default='admin', help='Host for openvas target(s)')
    parser.add_argument('-p.18', '--plugins.openvas.password', default='admin', help='Password for openvas target(s)')


    parser.add_argument('--cfg', action=ActionConfigFile, help='Config file input')

    args = parser.parse_args()
    print(args)

    in_file = args.file  # pylint: disable=no-member
    logging.info('Creating stix loader')
    sl = stix_loader(in_file=in_file)
    logging.warning('WE ARE IN TESTING MODE!!!')
    i = input('Ouput directory name: ')
    if os.path.exists(os.path.join(Handler.base_dir, i)):
        logging.critical(f'The directory path: {i} already exists, refusing to overwrite!')
        sys.exit()
    else:
        Handler.registerOutputDir(i)
    Handler.registerSTIXLoader(sl)
    Handler.registerLogger()

    Handler.startPCAP(interface=args.interface) # pylint: disable=no-member
    logging.info('Creating plugin runner')
    pr = plugin_runner(args, sl)
    logging.info('Running on plugin runner')
    pr.run()
    Handler.finish()
