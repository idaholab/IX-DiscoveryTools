from jsonargparse import ArgumentParser, ActionConfigFile
from loader import stix_loader
from runner import plugin_runner
from plugins.nmap import nmap
from util.handler import Handler
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
    parser.add_argument('-p.1', '--plugins.network.nmap', help='CIDR network to run nmap on')# this gets called no matter what..
    parser.add_argument('-p.2', '--plugins.network.sudo', action='store_true', default=False, help='run nmap as sudo, some TCP/IP fingerprinting requires this')
    parser.add_argument('-p.3', '--plugins.network.nmap_args', default=None, help='additional args for nmap')
    parser.add_argument('-p.4', '--plugins.network.no_services', action='store_true', default=False, help='prevents the nmap plugin from adding services')
    parser.add_argument('-p.5', '--plugins.pcap.file',  help='file to ingest for pcap plugin')
    parser.add_argument('-p.6', '--plugins.cve', action='store_true', help='whether or not to run cve_search')
    parser.add_argument('-p.7', '--plugins.remote.csv', help='csv cred file for remote information gathering')
    parser.add_argument('--cfg', action=ActionConfigFile, help='Config file input')

    args = parser.parse_args()
    
    in_file = args.file
    logging.info('Creating stix loader')
    sl = stix_loader(in_file=in_file)
    print('WE ARE IN TESTING MODE!!!')
    i = input('Ouput directory name: ')
    if os.path.exists(i):
        print(f'The directory path: {i} already exists, refusing to overwrite!')
        sys.exit()
    else:
        Handler.registerOutputDir(i)
    Handler.registerSTIXLoader(sl)
    Handler.registerLogger()
    Handler.startPCAP()
    logging.info('Creating plugin runner')
    pr = plugin_runner(args, sl)
    logging.info('Running on plugin runner')
    pr.run()
    Handler.finish()