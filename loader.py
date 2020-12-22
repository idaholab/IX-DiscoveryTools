from stix2 import MemoryStore, Infrastructure, Relationship

#should only need for dev
from pprint import pprint
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
            'relationship': Relationship
        }

    def read_in(self):
        self.create_blank()
        print('trying to read in: ', self.in_file)
        self.ms.load_from_file(self.in_file)

        objects = self.ms_source.query()

        for obj in self.ms._data.values():
            pprint(type(obj))
        print(self.ms)

        fixed_items = objects[:]
        for index, item in enumerate(objects):
            if type(item) == dict and item['type'] in fix_table:
                fixed_items[index] = fix_table[item['type']](allow_custom=True, **item)

        # self.objects = fixed_items

    def create_blank(self):
        self.ms = MemoryStore(allow_custom=True)
        self.ms_source = self.ms.source
        self.ms_sink = self.ms.sink

    def write_out(self, path):
        self.ms.save_to_file(path)