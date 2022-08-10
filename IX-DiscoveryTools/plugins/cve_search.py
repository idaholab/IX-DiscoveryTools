#Copyright 2021, Battelle Energy Alliance, LLC
import logging
from autodiscover.plugins.search import cve_searcher
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
        valid_props = ['x_protocol_inl', 'x_cpe_inl', 'x_por_inl', 'x_banner_inl', 'x_service_inl']
        objects = self.get_software()
        for obj in objects:
            x = True
            f = {'filters': [], 'target': obj}
            logging.debug(obj)
            #TODO: Check validity
            d = {}
            if 'x_protocol_inl' in obj.extensions:
                d['protocol'] = obj.extensions['x_protocol_inl']
            if 'x_cpe_inl' in obj.extensions:
                #TODO: foreach obj['x_cpe']
                d['cpe'] = obj.extensions['x_cpe_inl'][0]
            else:
                logging.debug(f'\n NO CPE FOR THIS OBJ: {obj}')
                x = False
            if 'x_port_inl' in obj.extensions:
                d['port'] = obj.extensions['x_port_inl']
            if 'x_banner_inl' in obj.extensions:
                d['banner'] = obj.extensions['x_banner_inl']
            if x == True:
                f['filters'].append(d)

            if f['filters'] != []:
                logging.debug(f"filters: {['filters']}")
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
        # logging.debug(self.data)
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

        filters = self.gen_filters_software()

        logging.info('filters: %s', filters)

        for f in filters:
            x = 0
            logging.debug(f'\n FILTER: {f}')

            for p in f['filters']:
                try:
                    if p and p['cpe']:
                        logging.debug(f['target'].extensions)
                        if f['target'].extensions['x_banner_inl']:
                            # pass
                            logging.debug(f"Searching {f['target'].extensions['x_banner_inl']}:")
                        #decode cpe
                        logging.debug('our cpe: %s', p['cpe'])
                        logging.info('our cpe: %s', p['cpe'])
                        ar = self.decode(p['cpe'])
                        logging.debug(ar)
                        # logging.debug(ar.cpe)
                        vuln_cves = c.search_pass(cpe=ar)
                        logging.debug(vuln_cves)
                        # vuln_cves = c.search(cpe=p['cpe'])
                        l += self.add_cves(vuln_cves, f['target'])

                except AttributeError as e:
                    logging.exception(e)


        self.stix_loader.merge(l)
        logging.info('finishing cve_search plugin')
