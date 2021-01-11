from plugins.nmap import nmap
from plugins.pcap import pcap
from plugins.cve_search import cve_search
import logging

class plugin_runner:
    def __init__(self, args, stix_loader):
        self.args = args
        self.stix_loader = stix_loader

    def run(self):
        """
        Runs all plugins that are set up via either config file or args passed in
        Checks for each plugin and calls the each runner
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

        if self.args.plugins.cve:
            c = cve_search(self.args, self.stix_loader)
            c.run()
        
        self.stix_loader.write_out(self.args.dest)