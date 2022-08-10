#Copyright 2021, Battelle Energy Alliance, LLC
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from stix2 import Infrastructure, parse, Relationship, Bundle, Software, IPv6Address, IPv4Address, MACAddress, DomainName
from autodiscover.util.helper import gen_uuid, fix_stix
import logging
from autodiscover.util.handler import Handler
from tqdm import tqdm
from time import sleep


def mapper(d, obj):
    l = {}
    for key in d:
        if hasattr(obj, d[key]) and getattr(obj, d[key]):
            l[key] = getattr(obj, d[key])
    return l

class nmap:
    def __init__ (self, args, stix_loader, nmap_args=None):
        self.args = args
        self.stix_loader = stix_loader
        command_string = ''
        if not self.args.plugins.network.nmap_args is None:
            command_string += f' {self.args.plugins.network.nmap_args}'
        if not self.args.plugins.network.no_services is None:
            command_string += f" -sV"
        if self.args.plugins.network.sudo:
            command_string += f" -O"
        if self.args.plugins.network.no_host_discovery:
            command_string += f" -Pn"
        else:
            # PE = basic ping (echo), PS= SYN packet, 
            command_string += f" -PE -PS21-23,25,53,80,139,443,445,3389"
        if self.args.plugins.network.do_not_resolve_hosts:
            command_string += f" -n"
        logging.info(command_string)
        self.nm = NmapProcess(args.plugins.network.nmap, options=command_string)


    def link_to_obj(self, src_obj, dst_list, relationship='has'):
        l = []
        if isinstance(dst_list, list):
            for dst in dst_list:
                rel = Relationship(source_ref=src_obj, relationship_type=relationship, target_ref=dst)
                l.append(rel)
        else:
            rel = Relationship(source_ref=src_obj, relationship_type=relationship, target_ref=dst_list)
            l.append(rel)
        return l

    def add_hostname(self, objs, relationship='has'):
        l = []
        if isinstance(objs, list):
            for obj in objs:
                if hasattr(obj, 'x_hostname'):
                    d = DomainName(value=obj.x_hostname)
                    rel = Relationship(source_ref=obj, relationship_type=relationship, target_ref=d)
                    l.extend([rel, d])
        else:
            if hasattr(objs, 'x_hostname'):
                d = DomainName(value=objs.x_hostname)
                rel = Relationship(source_ref=objs, relationship_type=relationship, target_ref=d)
                l.extend([rel, d])
        return l

    def process_service(self, services):
        if self.args.plugins.network.no_services:
            return []
        l = []
        for serv in services:
            if not serv.open():
                continue
            d = {'x_cpe': 'cpelist',
            'x_service': 'service',
            'x_port' : 'port',
            'x_protocol' : 'protocol',
            'x_banner': 'banner'}
            d = mapper(d, serv)

            v = {'x_vendor': 'vendor',
            'x_product': 'product',
            'x_hostname' : 'hostname',
            # 'x_name' : 'name',
            'x_extrainfo': 'extrainfo',
            'x_version': 'version',
            'x_ostype': 'ostype'}

            for key, value in v.items():
                if value in serv.service_dict.keys():
                    d[key] = serv.service_dict[value]

            if 'x_cpe' in d.keys():
                cpelist = []
                for item in d['x_cpe']:
                    cpelist.append(item.cpestring.replace('/','2.3:'))
                d['x_cpe'] = cpelist

            if 'x_product' in d.keys():
                d['name'] = f"{d['x_product']}"
            elif 'x_banner' in d.keys():
                d['name'] = f"{d['x_service']} - {d['x_banner']}"
            else:
                d['name'] = f"{d['x_service']}"


            #TODO HELPER FUNCTION (param = class (software, process,etc), dictionary)
            #TODO: returns created object (extensions:())
            #TODO: dict.keys(startswith(x_)) key.add +'_INL'
            s = fix_stix(Software, d, 'software')
            # s = Software(id=gen_uuid('software'), **d, allow_custom=True)

            l.append(s)
            logging.debug(f'software obj: {s}')
        return l

    def run(self, sudo):
        if sudo == True:
            logging.info('Running scan as root')
            self.nm.sudo_run_background(run_as='root')
        else:
            logging.info('Running scan without sudo')
            self.nm.run_background()
        total = 100
        with tqdm(total=total, desc='Scanning') as pbar:
            cur = 0
            while self.nm.is_running():
                new = float(self.nm.progress) - cur
                pbar.update(new)
                cur += new
                sleep(.5)
            pbar.update(total-cur)

        if self.nm.rc != 0:
            logging.critical('{self.nm.stderr}')
        logging.info("Scan finished... Parsing...")
        try:
            output = self.nm.stdout

            if Handler.output_active:
                Handler.OutputText(output, 'nmap.txt')
            self.results = NmapParser.parse(output)
        except NmapParserException as e:
            logging.exception(f"Exception raised while parsing scan: {e.msg}")

        l = []

        for host in self.results.hosts:
            if not host.is_up():
                continue

            if len(host.os_class_probabilities()):
                os = host.os_class_probabilities().pop()
            else:
                os = None

            if len(host.hostnames):
                tmp_host = host.hostnames.pop()
            elif os:
                tmp_host = os.description
            elif host.address:
                tmp_host = host.address
            else:
                tmp_host = host.mac

            ff = {'name': tmp_host, 'x_NIC_vendor': host.vendor}
            logging.debug('test: ', ff)
            host_obj = fix_stix(Infrastructure, ff, 'infrastructure')
            # host_obj = Infrastructure(id=gen_uuid('infrastructure'),name=tmp_host, allow_custom=True, x_NIC_vendor=host.vendor)
            logging.info(f'host obj: {host_obj}')
            l.append(host_obj)

            if os:

                d = {'name':'description',
                'cpe': 'cpe',
                'x_accuracy': 'accuracy',
                'vendor': 'vendor'}

                d = mapper(d, os)
                # d['allow_custom'] = True
                # d['id'] = gen_uuid('software')

                # s = Software(**d)
                s = fix_stix(Software, d, 'software')

                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)
                logging.debug(f'os obj: {s}')

            for item in [(host.ipv4, IPv4Address), (host.ipv6, IPv6Address),
            (host.mac, MACAddress), (host.hostnames, DomainName)]:
                if item[0]:
                    value = item[0]
                    obj = item[1]
                    if not isinstance(item[0], list):
                        value = [value]
                    for single in value:
                        s = obj(value=single)
                        rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                        l.append(s)
                        l.append(rel)
                        logging.info(f'Adding {type(obj)}: {s}')

            service_objs = self.process_service(host.services)
            rels = self.link_to_obj(host_obj, service_objs)
            l += service_objs
            l += self.add_hostname(service_objs)
            l += rels

        logging.info(f'End of nmap plugin')
        self.stix_loader.merge(l)
