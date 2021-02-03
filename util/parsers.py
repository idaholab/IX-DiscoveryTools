from pprint import pprint
import json
from stix2 import Infrastructure, Relationship, Process
from stix2.datastore import Filter, FilterSet
from util.helper import gen_uuid
import logging



class MainParser:
    def __init__(self):
        pass

    def parse(self, text, infra_obj):
        lines = text.split('\n')
        self.data =  {}
        (_, self.data[lines[0]]) = self.stack(self.count_prefix(lines[0]), lines[1:])
        (items_to_connect, objs) = self.to_stix()
        objs.extend(self.connect(items_to_connect, infra_obj))
        return objs

    def connect(self, items_to_connect, infra):
        l = []
        for item in items_to_connect:
            l.append(Relationship(source_ref=infra, target_ref=item, relationship_type='has'))
        return l
        
    
    def to_stix(self):
        objs = []
        for key in self.data:
            (main_obj, p_objs)= self.create_object(key, self.data[key])
            objs.extend(p_objs)
            objs.append(main_obj)
        return ([main_obj], objs)



    def create_object(self, name, data):
        attribs = {}
        objs_to_connect = []
        objs = []

        for key, value in data.items():
            if isinstance(value, dict):
                (main_child, child_objs) = self.create_object(key, value)
                objs.extend(child_objs)
                objs_to_connect.append(main_child)
            elif isinstance(value, str):
                attribs[f'x_{key}'] = value
            else:
                attribs[f'x_{key}'] = value
                logging.warning(f'Weird type of {type(value)} created when parsing text')

        attribs['name'] = name
        attribs['id'] = gen_uuid('infrastructure')
        hardware = Infrastructure(**attribs, allow_custom=True)

        for obj_to_connect in objs_to_connect:
            objs.append(self.link(hardware, obj_to_connect, rel_type='has'))
            objs.append(obj_to_connect)
        return (hardware, objs)

    @staticmethod
    def link(src, dst, rel_type='related-to'):
        return Relationship(source_ref=src, target_ref=dst, relationship_type=rel_type)

    @staticmethod
    def process_key(text):
        text = text.lstrip().rstrip()
        prefix = '*-'
        if text.startswith(prefix):
            text = text[len(prefix):]
        return  text
    
    def stack(self, main_count, lines):
        l = {}
        next_count = self.count_prefix(lines[0])
        skipper = 0
        processed = 0
        for index, line in enumerate(lines):
            processed += 1
            if skipper > 0:
                skipper -= 1
                continue
            elif self.count_prefix(line) < next_count and self.count_prefix(line) > main_count:
                (to_skip, l[self.process_key(line)]) = self.stack(self.count_prefix(line), lines[index+1:])
                skipper += to_skip
            elif self.count_prefix(line) == next_count:
                sections = line.split(':', 1)
                l[self.process_key(sections[0])] = sections[1].lstrip()
            elif line == '':
                continue
            else:
                processed -= 1
                break
        return (processed, l)

    def count_prefix(self, line):
        return len(line) - len(line.lstrip(' '))

class ProcessParser:
    def __init__(self,  delimter=None):
        self.delimter = delimter

    @staticmethod
    def link(src, dst, rel_type='related-to'):
        return Relationship(source_ref=src, target_ref=dst, relationship_type=rel_type)

    def parse(self, text, infra_obj):
        l = []
        lines = text.split('\n')
        counter = 0
        self.header = []
        while self.header == [] or self.header == ['']:
            if self.delimter is None:
                self.header = lines[counter].split()
            else:
                self.header = lines[counter].split(self.delimter)
            counter += 1
        for line in lines[counter:]: 
            if self.delimter is None:
                items = line.split()
            else:
                items = line.split(self.delimter)
            if items == [] or items == ['']:
                continue
            obj = self.create_object(items)
            l.append(obj)
            rel = self.link(infra_obj, obj)
            l.append(rel)
        return l

    def create_object(self, items):
        attrib = {}

        for index, value in enumerate(items):
            if self.header[index] == 'CMD' or self.header[index] == 'Name':
                attrib['name'] = value
                attrib['command_line'] = value
            elif self.header[index] == 'PID' or self.header[index] == 'ProcessId':
                attrib['pid'] = value
            else:
                attrib[f'x_{self.header[index]}'] = value
        attrib['id'] = gen_uuid('process')
        attrib['allow_custom'] = True
        return Process(**attrib)

