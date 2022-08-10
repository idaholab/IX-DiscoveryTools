#Copyright 2021, Battelle Energy Alliance, LLC\
import csv
import logging
from autodiscover.util.helper import get_infrastructure_by_ip
from stix2 import Infrastructure, IPv4Address, Relationship

class CSVFetcher:
    def __init__(self, stix_loader, csv_path):
        self.stix_loader = stix_loader
        self.sink = self.stix_loader.ms_sink
        self.source = self.stix_loader.ms_source
        with open(csv_path) as f:
            c = csv.DictReader(f)
            self.rows = [row for row in c]

    def get_targets(self):
        l = []
        for row in self.rows:
            infra = self.get_obj_or_create(row['ip'])
            l.append((infra, row['ip'], row['port']))
        return l

    def get_obj_or_create(self, ip):
        obj = get_infrastructure_by_ip(self.stix_loader, ip)
        if obj is None:
            ip_obj = IPv4Address(value=ip)
            infra = Infrastructure(name=ip_obj.value)
            rel = Relationship(source_ref=infra, relationship_type='has', target_ref=ip_obj)
            self.stix_loader.merge([ip_obj, infra, rel])
            return infra
        else:
            return obj

    def get_creds(self, ip, port):
        for row in self.rows:
            if row['ip'] == ip and row['port'] == port:
                return (row['username'], row['password'])

class STIXFetcher:
    def __init__(self, stix_loader):
        pass

class InputFetcher:
    def __init__(self):
        pass
