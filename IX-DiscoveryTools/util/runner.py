#Copyright 2021, Battelle Energy Alliance, LLC
from autodiscover.plugins.nmap import nmap
from autodiscover.plugins.pcap import pcap
from autodiscover.plugins.cve_search import cve_search
from autodiscover.plugins.remote_info import RemoteInfo
from autodiscover.plugins.openvas import OpenVAS
from autodiscover.plugins.unconstrained_dataflow import PacketProcessor
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
            print(self.args.plugins.network.nmap)
            if self.args.plugins.network.nmap:
                logging.info('starting nmap plugin')
                nm = nmap(self.args, self.stix_loader)
                nm.run(plugins.sudo)
        except Exception as e:
            logging.exception(f'Caught exception in nmap plugin: {e}')

        if self.args.plugins.pcap.file:
            if self.args.plugins.pcap.enhanced:
                p = PacketProcessor(self.args, self.stix_loader, pcap=self.args.plugins.pcap.file)
                p.run()
            else:
                p = pcap(self.args, self.stix_loader, file=self.args.plugins.pcap.file)
                p.run()

        if self.args.plugins.cve:
            c = cve_search(self.args, self.stix_loader)
            c.run()

        if self.args.plugins.remote.csv:
            c = RemoteInfo(self.args, self.stix_loader)
            c.run()
        try:
            if self.args.plugins.openvas.host or self.args.plugins.openvas.file:
                c = OpenVAS(self.args, self.stix_loader)
                c.run()
        except Exception as e:
            logging.exception(e)

        self.stix_loader.write_out(self.args.dest)
