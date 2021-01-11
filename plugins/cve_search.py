import logging

class cve_search:
    def __init__ (self, args, stix_loader):
        self.args = args
        self.stix_loader = stix_loader
        # self.file = file

    def run(self):
        l = []
        logging.info('running cve_search plugin')
        #we need to get a list of ip objects:
        #follow back to infra object
        #then out to software objects, compile list of proto/ports
        #search pcap for ip/proto[tcp/udp]/port combinations
            # for the moment we need to make sure the other ip address is in our list as well
                #Could always do crazy mode here as well.
        #create network traffic object to hold an example
        # one for each direction
        #   then we can always try crazy mode were we make one for each match
        self.stix_loader.merge(l)
        logging.info('finishing cve_search plugin')


        self.stix_loader.merge(l)