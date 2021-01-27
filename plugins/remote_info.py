import logging
from stix2 import Infrastructure, IPv4Address, Relationship, Software, NetworkTraffic
from stix2.datastore import Filter, FilterSet
from util.util import gen_uuid
from util.fetchers import CSVFetcher
from util.remoteconnectors import SSHConnectionFabric
from util.commandgroups import CommandGroups

class RemoteInfo:
    def __init__(self, args, stix_loader):
        logging.info('Creating RemoteInfo object')
        self.stix_loader = stix_loader
        self.args = args
        

    def run(self):
        if self.args.plugins.remote.csv:
            target_fetcher = CSVFetcher(self.args.plugins.remote.csv)
            cred_fetcher = target_fetcher

        targets = target_fetcher.get_targets()
        for target in targets:
            ip = target[0]
            port = target[1]
            (username, password) = cred_fetcher.get_creds(ip, port)

            if int(port) == 22:
                connector = SSHConnectionFabric(ip, port, user=username, password=password)
            
            for commandgroup in CommandGroups:
                commandgroup.register(connector)
                if commandgroup.test():
                    commandgroup.run()




