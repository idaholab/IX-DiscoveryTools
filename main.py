import argparse
from loader import stix_loader
from runner import plugin_runner


if __name__ == "__main__":
    ### Insert argparse stuff here!
    
    ### currently assuming the args will end up in "args"
    args = None
    ### assuming in_file will end up in "in_file"
    in_file = None
    out_file = None

    ### this should be the code needed to run the rest
    sl = stix_loader(in_file=in_file)
    pr = plugin_runner(args, sl)
    pr.run()
    sl.write_out(out_file)
    
