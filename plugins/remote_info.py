import logging
from stix2 import Infrastructure, IPv4Address, Relationship, Software, NetworkTraffic
from stix2.datastore import Filter, FilterSet
from util.helper import gen_uuid
from util.fetchers import CSVFetcher
from util.remoteconnectors import SSHConnectionFabric, PSConnection, PSConnectionSSL
from util.commandgroups import CommandGroups

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

            if int(port) == 22:
                connector = SSHConnectionFabric(ip, port, user=username, password=password)
            elif int(port) == 5985:
                connector = PSConnection(ip, port, user=username, password=password)
            elif int(port) == 5986:
                connector = PSConnectionSSL(ip, port, user=username, password=password)
            
            types = []
            if self.args.plugins.remote.hardware:
                types.append('hardware')
            if self.args.plugins.remote.process:
                types.append('process')
            for commandgroup in CommandGroups:
                commandgroup.register(connector)
                if commandgroup.test():
                    objs = commandgroup.run(infra, types)
                    self.stix_loader.merge(objs)




