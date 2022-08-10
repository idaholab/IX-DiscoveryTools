#Copyright 2021, Battelle Energy Alliance, LLC
from stix2 import MemoryStore, Infrastructure, Relationship, Software
from stix2.base import STIXJSONEncoder
import logging
from autodiscover.util.handler import Handler
from autodiscover.util.helper import gen_uuid
import json

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


        logging.debug(str(objects))
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
        #We are not using the built in .save_to_file as its slow for some reason
        logging.debug(f'attempting to write_out to path: {path}')
        logging.info('Starting save to file')
        # self.ms.save_to_file(path)
        d = {"type": "bundle",
          "id": gen_uuid('bundle'),
          "objects": [item for item in self.ms_source.query()]}

        with open(path, 'w') as f:
            json.dump(d, f, cls=STIXJSONEncoder)
        logging.info('Finished save to file')

    def get_sink_data(self):
        return self.ms.sink._data


    def merge(self, items):
        #need to make this do a proper merge later
        #self.ms_sink.add(items)
        logging.info('Merging:')
        for item in items:
            logging.debug(f'Adding:\n {item}')
            self.ms_sink.add(item)
        Handler.stixoutput()

    def quiet_merge(self, items):
        #need to make this do a proper merge later
        #self.ms_sink.add(items)
        for item in items:
            logging.debug(f'Adding:\n {item}')
            self.ms_sink.add(item)