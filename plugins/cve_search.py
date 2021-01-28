import logging

class cve_search:
    def __init__ (self, args, stix_loader):
        self.args = args
        self.stix_loader = stix_loader
        # self.file = file

    def run(self):
        l = []
        logging.info('running cve_search plugin')

        #Translate cpe to args to pass 




        self.stix_loader.merge(l)
        logging.info('finishing cve_search plugin')
