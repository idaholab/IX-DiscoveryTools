import logging
from plugins.search import cve_searcher
from stix2 import Software, Relationship
import re
class cve_search:
    
    def __init__ (self, args, stix_loader):
        self.args = args
        self.stix_loader = stix_loader
        # self.file = file
        # self.objects = stix_loader.objects

    def get_software(self):
        l = []
        objs = self.stix_loader.ms_source.query()
        for index, item in enumerate(objs):
            if type(item) == Software:
                l.append(item)
        return l

    def gen_filters_software(self):
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
            # for prop in obj:
            #     print('prop: ', prop)
            #     if prop.lower() in valid_props:
            #         print('correct property: ', prop)
            #         d = {}
            #         if 'x_protocol' in obj:
            #             d['protocol'] = obj['x_protocol']
            #         if 'x_cpe' in obj:
            #             #TODO: foreach obj['x_cpe']
            #             d['cpe'] = obj['x_cpe'][0]
            #         if 'x_port' in obj:
            #             d['port'] = obj['x_port']
            #         if 'x_banner' in obj:
            #             d['banner'] = obj['x_banner']
            #         f['filters'].append(d)

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
            # self.ms_sink.add(c)
            # self.ms_sink.add(rel)

            # rels = self.link_to_obj(host_obj, service_objs)
            l += c
            l += rel
            # l += rels
        return(l)

    def decode(self, cpe):
        print('----------------------')
        print('OUR CPE: ',cpe)
        print('----------------------')
        string = cpe

        string = string.replace('\\\\', '\\')
        data = re.split(r'(?<!\\):', string)
        #we need to pad the list for the next part
        data += [None] * (13 - len(data))

        print('xxxx')
        print(data)
        print('xxxx')

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

        print(self.cpe)
        print(self.cpe_version)
        print(self.part)
        print(self.version)
        print(self.vendor)
        print(self.product)
        # print(self.data)

        return data

    def run(self):
        l = []
        logging.info('running cve_search plugin')
        
        args2 = self.args
        sl = self.stix_loader

        # obj = self.objects
        # obj = self.stix_loader.ms_source.query #TODO CHANGE objects to this
        # print(obj)
        # logging.info('our args: ', self.args)
        # logging.info(args2)
        # logging.info(self.stix_loader)
        # logging.info('our stix_loader: ', stix_loader)
        #Translate cpe to args to pass 
        c = cve_searcher(proc_num=4)

        # c = cve_searcher(proc_num=args['num_procs'])
        load = cve_search
        filters = load.gen_filters_software(self)

        logging.info('filters: ', filters)
        # logging.info('CPE: ', filters[0].cpe)

        for f in filters:
            x = 0
            print('\n FILTER: ', f)

            # print('\n TESTING: ', f['filters']['cpe'])
            for p in f['filters']:
                # print('looking for cpe', p['cpe'])
                try:
                    if p and p['cpe']:
                        if f['target'].x_banner:
                            print(f"Searching {f['target'].x_banner}:")
                        #decode cpe
                        logging.info('our cpe: ', p['cpe'])
                        ar = load.decode(self, p['cpe'])
                        print(ar)
                        # print(ar.cpe)
                        vuln_cves = c.search2(cpe=ar)
                        print(vuln_cves)
                        # vuln_cves = c.search(cpe=p['cpe'])
                        print('*' * 80)
                        l += load.add_cves(self, vuln_cves, f['target'])
                        
                except AttributeError as e:
                    print(e)
        

        self.stix_loader.merge(l)
        logging.info('finishing cve_search plugin')
