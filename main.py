import argparse
from loader import stix_loader
from runner import plugin_runner
from nmap import nmap
import pathlib
# import logging #TODO: eventually add logging

#~/repos/GTO/elevator_work/AIS_FEED/stix2/2020-07-04/AIS_83592a65-c426-4fa9-bc27-b26a4ecbe75d_s2020_07_04T10_58_06_00_00.json

def ext_check(expected_extension):
    """
    Check for file extension to match json for argparse in_file/out_file
    """
    def extension(filename):
        if not filename.lower().endswith(expected_extension):
            raise ValueError()
        return filename
    return extension
    
def cipr_check(cipr):
    """
    Do something similar to check for proper CIDR input on nmap arg
    """

if __name__ == "__main__":
    ### Insert argparse stuff here!
    
    ### currently assuming the args will end up in "args"
    parser = argparse.ArgumentParser(description='IX AutoDiscover Utility.')
    parser.add_argument('--file', type=ext_check('.json'), help='Path to stix file to read in')
    parser.add_argument('--network', help='nmap with CIDR network path')
    parser.add_argument('--dest', type=ext_check('.json'), help='Path to save stix bundle')

    args = parser.parse_args()
    
    ### assuming in_file will end up in "in_file"
    in_file = args.file
    out_file = args.dest
    network = args.network

    if in_file:
        sl = stix_loader(in_file=in_file)
        pr = plugin_runner(args, sl)
        pr.run()
        sl.write_out(out_file)
    ### this should be the code needed to run the rest

    sl = stix_loader(in_file=in_file)

    nm = nmap(args, sl)
    nm.run()

    sl.write_out('test.json')

    # test nmap call
