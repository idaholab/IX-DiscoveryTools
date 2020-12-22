from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


class nmap:
    def __init__ (self, args, stix_loader):
        self.args = args
        self.stix_loader = stix_loader
        self.nm = NmapProcess(self.args.network, options="-sV")

    def run(self):
        rc = self.nm.run()

        if self.nm.rc != 0:
            print(self.nm.stderr)

        try:
            self.results = NmapParser.parse(self.nm.stdout)
        except NmapParserException as e:
            print("Exception raised while parsing scan: {0}".format(e.msg))

        
        for host in self.results.hosts:
            if len(host.hostnames):
                tmp_host = host.hostnames.pop()
            else:
                tmp_host = host.address
            print("Nmap scan report for {0} ({1})".format(
                tmp_host,
                host.address))

        for serv in host.services:
            # pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
            #         str(serv.port),
            #         serv.protocol,
            #         serv.state,
            #         serv.service,
            #         )
            print(str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service, serv.cpelist, serv.banner)
            # if len(serv.banner):
            #     pserv += " ({0})".format(serv.banner)
            # print(pserv)
    