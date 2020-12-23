from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from stix2 import Infrastructure, parse, Relationship, Bundle, Software, IPv4Address, MACAddress, DomainName


def mapper(d, obj):
    l = {}
    for key in d:
        if hasattr(obj, d[key]) and getattr(obj, d[key]):
            l[key] = getattr(obj, d[key])
    return l
class nmap:
    def __init__ (self, args, stix_loader):
        self.args = args
        self.stix_loader = stix_loader
        self.nm = NmapProcess(self.args.network, options="-sV -O")

    
    def run(self):
        rc = self.nm.sudo_run(run_as='root')

        if self.nm.rc != 0:
            print(self.nm.stderr)

        try:
            self.results = NmapParser.parse(self.nm.stdout)
        except NmapParserException as e:
            print("Exception raised while parsing scan: {0}".format(e.msg))

        l = []

        for host in self.results.hosts:
            if len(host.os_class_probabilities()):
                os = host.os_class_probabilities().pop()

            if len(host.hostnames):
                tmp_host = host.hostnames.pop()
            elif os:
                tmp_host = os.description
            elif host.address:
                tmp_host = host.address
            else:
                tmp_host = host.mac


                        
            host_obj = Infrastructure(name=tmp_host, allow_custom=True)

            l.append(host_obj)

            if os:

                d = {'name':'description',
                'cpe': 'cpe',
                'x_accuracy': 'accuracy',
                'vendor': 'vendor'}

                d = mapper(d, os)
                d['allow_custom'] = True
            
                s = Software(**d)
                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)

            if host.address:
                s = IPv4Address(value=host.address)
                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)
            
            if host.mac:
                s = MACAddress(value=host.mac)
                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)

            if host.hostnames:
                for name in host.hostnames:
                    s = DomainName(value=name)
                    rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                    l.append(s)
                    l.append(rel)


            for serv in host.services:
                d = {'name':'service',
                'cpe': 'cpelist',
                'x_port' : 'port',
                'x_protocol' : 'protocol',
                'x_banner': 'banner'}

                d = mapper(d, serv)
                d['allow_custom'] = True
            
                s = Software(**d)
                rel = Relationship(source_ref=host_obj, relationship_type='has', target_ref=s)
                l.append(s)
                l.append(rel)

            
        self.stix_loader.merge(l)

                # pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                #         str(serv.port),
                #         serv.protocol,
                #         serv.state,
                #         serv.service,
                #         )
                # print(str(serv.port),
                #         serv.protocol,
                #         serv.state,
                #         serv.service, serv.cpelist, serv.banner)
            # if len(serv.banner):
            #     pserv += " ({0})".format(serv.banner)
            # print(pserv)

            # objects to make:
            # infrastructure - host
            # software - OS - service (add cpe) port protocol
            # ip object
            # mac object?
    