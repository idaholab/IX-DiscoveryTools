from plugins.nmap import nmap
from plugins.pcap import pcap
import logging

class plugin_runner:
    def __init__(self, args, stix_loader):
        self.args = args
        self.stix_loader = stix_loader

    def run(self):
        """
        here we need to figure out the plugins we 
        need to run from the args then run them
        Each will likely take the stix_loader as an argument,
        along with all the other args
        """
        plugins = self.args.plugins.network
        try:
            if self.args.plugins.network.nmap:
                logging.info('starting nmap plugin')
                nm = nmap(self.args, self.stix_loader)
                x = nm.run(plugins.sudo)
        except Exception as e:
            logging.exception(f'Caught exception in nmap plugin: {e}')

        if self.args.plugins.pcap.file:
            p = pcap(self.args, self.stix_loader, file=self.args.plugins.pcap.file)
            p.run()

        self.stix_loader.write_out(self.args.dest)