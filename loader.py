from stix2 import MemoryStore, Infrastructure, Relationship, Software
import logging
from util.handler import Handler

class stix_loader:
    def __init__(self, in_file=None):
        self.in_file = in_file


        if self.in_file is not None:
            self.read_in()
        else:
            self.create_blank()

        #we use this table to remap custom objects to the correct, add items as needed
        self.fix_table = {
            'infrastructure': Infrastructure,
            'relationship': Relationship,
            'software': Software
        }

    def read_in(self):
        self.create_blank()
        logging.info(f'trying to read in: {self.in_file}')
        self.ms.load_from_file(self.in_file)

        objects = self.ms_source.query()
        
        fixed_items = objects[:]
        for index, item in enumerate(objects):
            if type(item) == dict and item['type'] in self.fix_table:
                fixed_items[index] = self.fix_table[item['type']](allow_custom=True, **item)

        self.objects = fixed_items #TODO: was commented out before cve_search. Delete comment once M.Cutshaw acknowledges

    def create_blank(self):
        logging.info('Creating blank stix object')
        self.ms = MemoryStore(allow_custom=True)
        self.ms_source = self.ms.source
        self.ms_sink = self.ms.sink

    def write_out(self, path):
        #if this becomes slow I have a work around
        print('attempting to write_out to path: ', path)
        logging.info('Starting save to file')
        self.ms.save_to_file(path)
        logging.info('Finished save to file')

    def merge(self, items):
        #need to make this do a proper merge later
        #self.ms_sink.add(items)
        logging.info('Merging:')
        for item in items:
            logging.debug(f'Adding:\n {item}')
            self.ms_sink.add(item)
        Handler.stixoutput()
        
