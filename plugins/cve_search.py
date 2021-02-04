import logging
from plugins.search import cve_searcher
from stix2 import Software, Relationship
import re
class cve_search:
    
    def __init__ (self, args, stix_loader):
        self.args = args
        self.stix_loader = stix_loader


    def get_software(self):
        l = []
        objs = self.stix_loader.ms_source.query()
        for index, item in enumerate(objs):
            if type(item) == Software:
                l.append(item)
        return l

    def gen_filters_software(self):
        #TODO: don't think this really does anything in the way we are using it to just pass cpe.
        l = []
        valid_props = ['x_protocol', 'x_cpe', 'x_port', 'x_banner', 'x_service']
        objects = self.get_software()
        for obj in objects:
            x = True
            f = {'filters': [], 'target': obj}
            print(obj)
            #TODO: Check validity
            d = {}
            if 'x_protocol' in obj:
                d['protocol'] = obj['x_protocol']
            if 'x_cpe' in obj:
                #TODO: foreach obj['x_cpe']
                d['cpe'] = obj['x_cpe'][0]
            else:
                print('\n NO CPE FOR THIS OBJ: ', obj)
                x = False
            if 'x_port' in obj:
                d['port'] = obj['x_port']
            if 'x_banner' in obj:
                d['banner'] = obj['x_banner']
            if x == True:
                f['filters'].append(d)           

            if f['filters'] != []:
                print('filters: ', f['filters'])
                l.append(f)
        return l

    def add_cves(self, cves, obj):
        l = []
        for cve in cves:
            c = cve.to_stix()
            dst = c.id
            src = obj.id
            rel = Relationship(source_ref=obj, relationship_type='has', target_ref=c)

            l.append(c)
            l.append(rel)
        return(l)

    def decode(self, cpe):
        logging.info('----------------------')
        logging.info('OUR CPE: %s',cpe)
        logging.info('----------------------')
        string = cpe

        string = string.replace('\\\\', '\\')
        data = re.split(r'(?<!\\):', string)
        #we need to pad the list for the next part
        data += [None] * (13 - len(data))
        # print(self.data)
        (self.cpe,
        self.cpe_version,
        self.part, 
        self.vendor,
        self.product,
        self.version,
        self.update,
        self.edition,
        self.language,
        self.sw_edition,
        self.target_sw,
        self.target_hw,
        self.other) = data
        
        return data

    def run(self):
        l = []
        logging.info('running cve_search plugin')
  
        c = cve_searcher(proc_num=4)

        load = cve_search
        filters = load.gen_filters_software(self)

        logging.info('filters: %s', filters)

        for f in filters:
            x = 0
            print('\n FILTER: ', f)

            for p in f['filters']:
                try:
                    if p and p['cpe']:
                        if f['target'].x_banner:
                            print(f"Searching {f['target'].x_banner}:")
                        #decode cpe
                        logging.info('our cpe: %s', p['cpe'])
                        ar = load.decode(self, p['cpe'])
                        print(ar)
                        # print(ar.cpe)
                        vuln_cves = c.search_pass(cpe=ar)
                        print(vuln_cves)
                        # vuln_cves = c.search(cpe=p['cpe'])
                        print('*' * 80)
                        l += load.add_cves(self, vuln_cves, f['target'])
                        
                except AttributeError as e:
                    print(e)
        

        self.stix_loader.merge(l)
        logging.info('finishing cve_search plugin')
