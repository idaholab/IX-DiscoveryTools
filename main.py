import argparse
from loader import stix_loader
from runner import plugin_runner
from nmap import nmap
import pathlib
import shutil
# import logging #TODO: eventually add logging

def ext_check(expected_extension):
    """
    Check for file extension to match json for argparse in_file/out_file
    """
    def extension(filename):
        if not filename.lower().endswith(expected_extension):
            raise ValueError()
        return filename
    return extension
    
def config_check(configfile):
    """
    Check config file for plugins to use
    TODO: programatically accept a config file rather than hard coded config.dat
    """
    try:
        dest = './temp/backup'
        afile = open(configfile)
        plugz = []
        print(afile)
        #Iterate through list of plugins '\n'
        pluglist = afile.read().split('\n')
        print(pluglist)
        for plugin in pluglist:
            if plugin: #remove empty/newlines
                print('pluglist: ', plugin)
                plugz.append(plugin)
        
        print(plugz)
        return plugz
    except FileNotFoundError:
        pass

if __name__ == "__main__":
    ### Insert argparse stuff here!
    
    ### currently assuming the args will end up in "args"
    parser = argparse.ArgumentParser(description='IX AutoDiscover Utility.')
    parser.add_argument('-f', '--file', type=ext_check('.json'), help='Path to stix file to read in')
    parser.add_argument('-n', '--network', help='nmap with CIDR network path')
    parser.add_argument('-d', '--dest', type=ext_check('.json'), help='Path to save stix bundle')
    parser.add_argument('-p', '--plugins', type=config_check('config.dat'), help='file list of plugins with args to run')
    #TODO: nmap considered plugin?  Move here
    #TODO: add config file for args and/or plugins

    args = parser.parse_args()
    
    ### assuming in_file will end up in "in_file"
    in_file = args.file
    out_file = args.dest
    network = args.network

    if in_file:
        sl = stix_loader(in_file=in_file)
        pr = plugin_runner(args, sl)
        pr.run()
    else:
        sl = '' #sl required by nmap

    if out_file:
        sl.write_out(out_file)
    ### this should be the code needed to run the rest

    ### attempting plugins arg
    if args.plugins:
        print('true')
        print(args.plugins)
    if network:
        nm = nmap(args, sl)
        nm.run()

