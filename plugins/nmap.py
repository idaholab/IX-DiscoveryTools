from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from stix2 import Infrastructure, parse, Relationship, Bundle, Software, IPv6Address, IPv4Address, MACAddress, DomainName
from util import gen_uuid
import logging

def mapper(d, obj):
    l = {}
    for key in d:
        if hasattr(obj, d[key]) and getattr(obj, d[key]):
            l[key] = getattr(obj, d[key])
    return l

class nmap:
    def __init__ (self, args, stix_loader, top_ports=1000):
        self.args = args
        self.stix_loader = stix_loader
        self.nm = NmapProcess(args.plugins.network.nmap, options=f"-sV -O --top-ports {int(top_ports)}")

    def run(self, sudo):
        if sudo == True:
            logging.info('Running scan as root')
            rc = self.nm.sudo_run(run_as='root')
        else:
            logging.info('Running scan without sudo')
            rc = self.nm.run()

        if self.nm.rc != 0:
            logging.critical('{self.nm.stderr}')
        print("Scan finished... Parsing...")
        try:
            self.results = NmapParser.parse(self.nm.stdout)
        except NmapParserException as e:
            logging.exception(f"Exception raised while parsing scan: {e.msg}")

        l = []

        for host in self.results.hosts:
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

                        
            host_obj = Infrastructure(id=gen_uuid('infrastructure'),name=tmp_host, allow_custom=True)
            logging.info(f'host obj: {host_obj}')
            l.append(host_obj)

            if os:

                d = {'name':'description',
                'cpe': 'cpe',
                'x_accuracy': 'accuracy',
                'vendor': 'vendor'}

                d = mapper(d, os)
                d['allow_custom'] = True
            
                s = Software(id=gen_uuid('software'),**d)
                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)
                logging.debug(f'os obj: {s}')

            if host.ipv4:
                s = IPv4Address(value=host.ipv4)
                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)
                logging.debug(f'host ipv4 obj: {s}')

            if host.ipv6:
                s = IPv6Address(value=host.ipv6)
                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)
                logging.debug(f'host ipv6 obj: {s}')
            
            if host.mac:
                s = MACAddress(value=host.mac)
                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)
                logging.debug(f'mac obj: {s}')

            if host.hostnames:
                for name in host.hostnames:
                    s = DomainName(value=name)
                    rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                    l.append(s)
                    l.append(rel)
                    logging.debug(f'hostname obj: {s}')


            for serv in host.services:
                d = {'x_cpe': 'cpelist',
                'x_service': 'service',
                'x_port' : 'port',
                'x_protocol' : 'protocol',
                'x_banner': 'banner'}
                d = mapper(d, serv)
               
                if 'x_cpe' in d.keys():
                    cpelist = []
                    for item in d['x_cpe']:
                        cpelist.append(item.cpestring.replace('/','2.3:'))
                    d['x_cpe'] = cpelist

                if 'x_banner' in d.keys():
                    d['name'] = f"{d['x_service']} - {d['x_banner']}"
                else:
                    d['name'] = f"{d['x_service']}"
            

                s = Software(id=gen_uuid('software'), **d, allow_custom=True)

                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)
                logging.info(f'software obj: {s}')

        logging.info(f'End of nmap plugin')
        self.stix_loader.merge(l)