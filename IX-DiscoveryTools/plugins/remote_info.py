#Copyright 2021, Battelle Energy Alliance, LLC
import logging
from stix2 import Infrastructure, IPv4Address, Relationship, Software, NetworkTraffic
from stix2.datastore import Filter, FilterSet
from autodiscover.util.helper import gen_uuid
from autodiscover.util.fetchers import CSVFetcher
from autodiscover.util.remoteconnectors import SSHConnectionFabric, PSConnection, PSConnectionSSL, TelnetConnection
from autodiscover.util.commandgroups import CommandGroups
import traceback


class RemoteInfo:
    def __init__(self, args, stix_loader):
        logging.info('Creating RemoteInfo object')
        self.stix_loader = stix_loader
        self.args = args

    def run(self):
        if self.args.plugins.remote.csv:
            target_fetcher = CSVFetcher(self.stix_loader, self.args.plugins.remote.csv)
            cred_fetcher = target_fetcher

        targets = target_fetcher.get_targets()
        for target in targets:
            infra = target[0]
            ip = target[1]
            port = target[2]

            (username, password) = cred_fetcher.get_creds(ip, port)

            connector = None
            if int(port) == 22:
                connector = SSHConnectionFabric(ip, port, user=username, password=password)
            if int(port) == 23:
                connector = TelnetConnection(ip, port, user=username, password=password)
            elif int(port) == 5985:
                connector = PSConnection(ip, port, user=username, password=password)
            elif int(port) == 5986:
                connector = PSConnectionSSL(ip, port, user=username, password=password)

            if connector is None:
                logging.error('No valid connector created!!! Remote Info plugin Failed')
                return None

            types = []
            if self.args.plugins.remote.hardware:
                types.append('hardware')
            if self.args.plugins.remote.process:
                types.append('process')
            if self.args.plugins.remote.filetree:
                types.append('filetree')
            for commandgroup in CommandGroups:
                commandgroup.register(connector)
                if commandgroup.test():
                    objs = commandgroup.run(infra, types, self.args.plugins.remote)
                    self.stix_loader.merge(objs)
