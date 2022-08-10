#Copyright 2021, Battelle Energy Alliance, LLC
import logging
from stix2 import Infrastructure, IPv4Address, Relationship, Software, NetworkTraffic
from stix2.datastore import Filter, FilterSet
from autodiscover.util.helper import gen_uuid, multi_filt
from autodiscover.openvas.openVASAutomation import run_scan, CouldNotConnectToScanner
import docker
import time
from autodiscover.openvas.parser_w_bundle import parse_bundle
from autodiscover.util.handler import Handler
from xml.etree import ElementTree


class OpenVAS:
    def __init__ (self, args, stix_loader, file=None):
        # if file is None:
        #     logging.warning('There is no input pcap, the pcap plugin will do nothing...')
        self.args = args
        self.stix_loader = stix_loader
        self.file = file
        self.sink = self.stix_loader.ms_sink
        self.source = self.stix_loader.ms_source
        self.docker_client = docker.from_env()


    def connect_to_container(self):
        container_name = 'gvm_autodiscover'
        # we need to check if the docker container is Running
        # found_container = False
        try:
            self.container = self.docker_client.containers.get(container_name)
            if self.container.status != 'running':
                logging.info(f'trying to start docker container {container_name}')
                # if the docker container isn't we need to start it in a blocking way
                self.container.start()
                for _ in range(13):
                    time.sleep(5)
                    self.container = self.docker_client.containers.get(container_name)
                    if self.container.status != 'running':
                        logging.debug(self.container.status)
                        logging.info('Container still not up...')
                    else:
                        # found_container = True
                        break
                logging.error(f'Unable to start container?!?')
        except:
            logging.critical(f'No container named: {container_name} was found!!!')


    def run_scan(self):
        for _ in range(18):
            try:
                report = run_scan(host=self.args.plugins.openvas.host,
                            system_password=self.args.plugins.openvas.password,
                            system_login=self.args.plugins.openvas.username)
                return report
            except ConnectionResetError:
                time.sleep(10)

    def run(self):
        l = []
        logging.info('running openvas plugin')
        if self.args.plugins.openvas.file is not None:
            l.extend(parse_bundle(ElementTree.parse(self.args.plugins.openvas.file).find('./report/report'), self.stix_loader))
        else:
            self.connect_to_container()
            try:
                report = self.run_scan()
            except CouldNotConnectToScanner:
                logging.warning('Openvas could not connect to its scanner, trying to restart and retry')
                self.container.restart()
                self.connect_to_container()
                report = self.run_scan()
            
            
            
            Handler.OutputText(ElementTree.tostring(report, encoding='utf8', method='xml').decode(),'openvas.xml')
            # We need to verify that we can connect to it
            # we need to do our scan, wait for it to finish and return our etree
            l.extend(parse_bundle(report, self.stix_loader))
        # we need to process it into stix then return that stix
        self.stix_loader.merge(l)
        logging.info('finishing openvas plugin')
