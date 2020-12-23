from jsonargparse import ArgumentParser, ActionConfigFile
from loader import stix_loader
from runner import plugin_runner
from nmap import nmap
import pathlib
import shutil
import os 

# import logging #TODO: eventually add logging

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
    
# def config_check(configfile):
#     """
#     Check config file for plugins to use
#     Mainly parses a file into a list and then saves it to ./temp/plugin_config.txt.
#     Should be completely rewritten
#     TODO: programatically accept a config file rather than hard coded config.dat
#     """
#     try:
#         dest = './config/plugin_config.txt'
#         afile = open(configfile)
#         x = []
#         #Iterate through list of plugins '\n'
#         pluglist = afile.read().split('\n')
#         for plugin in pluglist:
#             if plugin: #remove empty/newlines
#                 print('pluglist: ', plugin)
#                 x.append(plugin)
#         with open(dest, 'w') as f:
#             for item in x:
#                 f.write("%s\n" % item)
#     except FileNotFoundError:
#         pass

#TODO:if nothing is passed in, create blank file

if __name__ == "__main__":
    plugin_list = './config/plugin_config.txt'
    ### Insert argparse stuff here!
    
    ### currently assuming the args will end up in "args"
    parser = ArgumentParser(description='IX AutoDiscover Utility.')
    parser.add_argument('-f', '--file', type=ext_check('.json'), help='Path to stix file to read in')
    parser.add_argument('-d', '--dest', type=ext_check('.json'), default='./temp/test.json', help='Path to save stix bundle')
    parser.add_argument('-p.1', '--plugins.nmap', help='CIDR network to run nmap on')# this gets called no matter what..
    parser.add_argument('-p.2', '--plugins.sudo', help='run nmap as sudo, some TCP/IP fingerprinting requires this')
    parser.add_argument('--cfg', action=ActionConfigFile)
    #TODO: add config file for args and/or plugins

    args = parser.parse_args()
    
    ### assuming in_file will end up in "in_file"
    in_file = args.file
    out_file = args.dest
    plugins = args.plugins

    if in_file:
        sl = stix_loader(in_file=in_file)
        pr = plugin_runner(args, sl)
        pr.run()
    else:
        sl = stix_loader() #sl required by nmap... If no in_file then we create a blank stix file

    if out_file:
        sl.write_out(out_file)

    if plugins.nmap:
        sudo = False
        if plugins.sudo:
            sudo = True
        print('running nmap with sudo as: ', sudo )
        nm = nmap(args, sl)
        x = nm.run(sudo)
        sl.write_out(out_file)

    # sl = stix_loader(in_file=in_file)
    # sl.write_out('test.json')
    # test nmap call
