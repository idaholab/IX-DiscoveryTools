#Copyright 2021, Battelle Energy Alliance, LLC
from pprint import pprint
import json
from stix2 import Infrastructure, Relationship, Process, Directory, File
from stix2.datastore import Filter, FilterSet
from datetime import datetime
from autodiscover.util.helper import gen_uuid
import logging
from parse import parse
import pdb, traceback, sys


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

class InfParser:
    '''
    Attempt at creating a
    '''
    def __init__(self,  delimter=None):
        self.delimter = delimter

class InfraParser:
    #TODO: REGEX OUT COMMA IN RETUREND
    def __init__(self,  delimter=None, name=None):
        self.delimter = delimter
        self.name = name

    @staticmethod
    def link(src, dst, rel_type='related-to'):
        return Relationship(source_ref=src, target_ref=dst, relationship_type=rel_type)

    def parse(self, text, infra_obj):
        l = []
        lines = text.split('\n')
        counter = 0
        self.header = []
        while self.header == [] or self.header == ['']:
            self.header = lines[counter].split(self.delimter)
            counter += 1
        logging.info(f'HEADER {self.header}')
        for line in lines[counter:]:
            items = line.split(self.delimter)
            if items == [] or items == ['']:
                continue
            obj = self.create_object(items)
            l.append(obj)
            rel = self.link(infra_obj, obj)
            l.append(rel)
        return l

    def create_object(self, items):
        '''
        PROBLEM WITH INDEX/VALUES THAT HAVE COMMA, REGEX IT OUT
        '''
        attrib = {}
        logging.debug('items: ', items)
        for index, value in enumerate(items):
            try:
                attrib['name'] = self.name
                if self.header[index] == '' or value == '':
                    continue
                elif self.header[index] == 'Name':
                    attrib['name'] = value
                else:
                    attrib[f'x_{self.header[index]}'] = value
            except Exception as e:
                logging.info(e)

        attrib['id'] = gen_uuid('infrastructure')
        attrib['allow_custom'] = True
        return Infrastructure(**attrib)

class ProcessParser:
    def __init__(self,  delimter=None):
        self.delimter = delimter

    @staticmethod
    def link(src, dst, rel_type='related-to'):
        return Relationship(source_ref=src, target_ref=dst, relationship_type=rel_type)

    def connect(self, items, infra_obj):
        l = []
        d = {}
        for item in items:
            d[item.pid] = item

        for item in items:
            #TODO fix section 7 subsection 4
            if hasattr(item, 'x_PPID'):
                ppid = int(item.x_PPID)
                if ppid in d.keys():
                    l.append(self.link(d[ppid], item))
                    continue
                l.append(self.link(infra_obj, item))
        return l

    def parse(self, text, infra_obj):
        l = []
        lines = text.split('\n')
        counter = 0
        self.header = []
        while self.header == [] or self.header == ['']:
            self.header = lines[counter].split(self.delimter)
            counter += 1
        logging.info(f'HEADER {self.header}')
        for line in lines[counter:]:
            items = line.split(self.delimter)
            if items == [] or items == ['']:
                continue
            obj = self.create_object(items)
            l.append(obj)
            # rel = self.link(infra_obj, obj)
            # l.append(rel)
        l.extend(self.connect(l, infra_obj))
        return l

    def create_object(self, items):
        attrib = {}
        for index, value in enumerate(items):
            try:
                if self.header[index] == 'CMD' or self.header[index] == 'Name':
                    attrib['name'] = value
                    attrib['command_line'] = value
                elif self.header[index] == 'PID' or self.header[index] == 'ProcessId':
                    attrib['pid'] = value
                else:
                    attrib[f'x_{self.header[index]}'] = value
            except Exception as e:
                logging.info(e)

        attrib['id'] = gen_uuid('process')
        attrib['allow_custom'] = True
        return Process(**attrib)

class FileObject:
    def process_line(self, line):
        def set_file_type(file_type):
            char_id = oct(int(file_type, 16))[-6:-4]
            if char_id == '14':
                return 'socket'
            elif char_id == '12':
                return 'symlink'
            elif char_id == '10':
                return 'file'
            elif char_id == '06' or char_id == 'o6':
                return 'block_device'
            elif char_id == '04' or char_id == 'o4':
                return 'directory'
            elif char_id == '02' or char_id == 'o2':
                return 'character_device'
            else:
                logging.warning(f'Unrecognized file type {file_type}! Defaulting to directory!')
                return 'directory'
        try:
            (self.path, self.perms, self.size, self.uid, self.user, self.gid,
            self.group, self.file_type, self.mtime, self.atime) = line.split(' ')

            self.path_list = self.path.lstrip('/').lstrip('./').split('/')
            self.name = self.path_list[-1]
            self.file_type = set_file_type(self.file_type)
            self.created = True
        except:
            traceback.print_exc()

    def __iter__(self):
        for child in self.children:
            yield child

    def __init__(self, line):
        self.created = False
        self.process_line(line)
        self.children = []

    def add_child(self, child):
        self.children.append(child)

    def place_in_tree(self, item, index):
        if item.path_list[index] == self.name:
            if index+2 == len(item.path_list):
                self.children.append(item)
                return True
            else:
                for child in self.children:
                    if child.place_in_tree(item, index+1):
                        return True
        return False

class FileTreeParser:
    def __init__(self,  delimter=None):
        self.delimter = delimter
        self.objects = []

    @staticmethod
    def link(src, dst, rel_type='contains'):
        return Relationship(source_ref=src, target_ref=dst, relationship_type=rel_type)

    def add_to_tree(self, d, fileobj):
        for item in d:
            if item.place_in_tree(fileobj, 0):
                return d
        d.append(fileobj)
        return d

    def objects_from_dict(self, d, parent):
        objs_l = []
        for fileobject in d:
            item = self.create_object(fileobject, [])
            subobjects = self.objects_from_dict(fileobject.children, item.id)
            item = self.create_object(fileobject, subobjects, with_id=item.id, parent=parent)
            for subobj in subobjects:
                self.objects.append(self.link(item, subobj))

            objs_l.append(item)
            self.objects.append(item)
        return objs_l

    def parse(self, text, infra_obj):
        l = []
        lines = text.split('\n')
        counter = 0
        d = []
        try:
            for line in lines:
                if line == '':
                    continue
                item = FileObject(line)
                if not item.created:
                    continue
                d = self.add_to_tree(d, item)

        except Exception as e:
            logging.exception(e)

        for item in self.objects_from_dict(d, None):
            self.objects.append(self.link(item, infra_obj))
        return self.objects

    def create_object(self, file_object, subobjects, with_id=None, parent=None):
        d = {}
        d['allow_custom'] = True

        d['name'] = file_object.name
        d['mtime'] = datetime.fromtimestamp(int(file_object.mtime))
        d['atime'] = datetime.fromtimestamp(int(file_object.atime))
        d['x_uid'] = file_object.uid

        d['x_user'] = file_object.user
        d['x_gid'] = file_object.gid
        d['x_group'] = file_object.group
        d['x_file_type'] = file_object.file_type
        d['x_permissions'] = file_object.perms
        d['contains_ref'] = [subobj.id for subobj in subobjects]
        if parent is not None:
            d['parent_directory_ref'] = parent
        # d['x_created_date'] = datetime.fromtimestamp(int(file_object.created))


        if file_object.file_type == 'directory':
            if with_id is None:
                d['id'] = gen_uuid('directory')
            else:
                d['id'] = with_id
            d['path'] = file_object.path # directory only

            return Directory(**d)

        else:
            if with_id is None:
                d['id'] = gen_uuid('file')
            else:
                d['id'] = with_id
            d['size'] = file_object.size # file only
            d['x_path'] = file_object.path # directory only
            return File(**d)

class DMIParser:
    def __init__(self):
        pass

    def split_header(self, lines):
        header = []
        for index, line in enumerate(lines):
            if line == '':
                return (header, lines[index+1:])
            header.append(line)
        logging.error('Failed to parse dmicode, unable to find end of header')
        return ([], [])

    def header_to_stix(self, header):
        pass

    def parse(self, text, infra_obj):
        lines = text.split('\n')

        self.data = {}
        (header, lines) = self.split_header(lines)
        l = []
        for item in self.split_list(lines):
            processed_item = self.handle_header(item)
            if not processed_item is None:
                obj = self.create_object(processed_item)
                l.append(obj)
                l.append(self.link(infra_obj, obj))
        return l

    def handle_header(self, lines):
        if (len(lines) < 3):
            return None
        stolen = lines[0:2]
        (_, new) = self.stack(self.count_prefix(lines[2]), lines[2:])

        (new['Handle'], new['DMI Type'], new['size (bytes)']) = parse("Handle {}, DMI type {}, {} bytes", lines[0])
        new['type'] = lines[1]
        return new

    @staticmethod
    def split_list(k, delimiter=''):
        l = []
        last = 0
        if k == []:
            return []
        for index, line in enumerate(k):
            if line == delimiter:
                l.append(k[last:index])
                last = index+1
            if index == len(k):
                l.append(k[last:index+1])
        if l[-1] == []:
            l.pop(len(l)-1)
        return l

    def connect(self, items_to_connect, infra):
        l = []
        for item in items_to_connect:
            l.append(Relationship(source_ref=infra, target_ref=item, relationship_type='has'))
        return l

    def create_object(self, data):
        attribs = {}

        for key, value in data.items():
            attribs[f'x_{key}'] = value
        attribs['name'] = attribs['x_type']

        if 'x_Socket Designation' in attribs.keys():
            attribs['name'] += attribs['x_Socket Designation']
        elif 'x_Designation' in attribs.keys():
            attribs['name'] += attribs['x_Designation']
        elif 'x_Locator' in attribs.keys():
            attribs['name'] += attribs['x_Locator']

        attribs['id'] = gen_uuid('infrastructure')
        hardware = Infrastructure(**attribs, allow_custom=True)

        return hardware

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

    def characteristics(self, main_count, lines):
        l = []
        processed = 0
        next_count = self.count_prefix(lines[0])
        for index, line in enumerate(lines):
            processed += 1
            if self.count_prefix(line) == next_count:
                l.append(self.process_key(line))
            else:
                processed -= 1
                break
        return (processed, l)

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
            elif 'Characteristics' in line:
                (to_skip, l[self.process_key(line)]) = self.characteristics(self.count_prefix(line), lines[index+1:])
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
        return len(line) - len(line.lstrip('\t'))

class CPUInfoParser:
    def __init__(self):
        pass

    def split_header(self, lines):
        header = []
        for index, line in enumerate(lines):
            if line == '':
                return (header, lines[index+1:])
            header.append(line)
        logging.error('Failed to parse dmicode, unable to find end of header')
        return ([], [])

    def parse(self, text, infra_obj):
        lines = text.split('\n')
        self.data = {}
        lines = self.split_list(lines)
        l = []
        for item in lines:
            processed_item = self.create_object(item)
            l.append(processed_item)
            l.append(self.link(infra_obj, processed_item))
        return l

    @staticmethod
    def split_list(k, delimiter=''):

        l = []
        last = 0
        for index, line in enumerate(k):
            if line == delimiter:
                l.append(k[last:index])
                last = index+1
            if index == len(k):
                l.append(k[last:index+1])
        if l[-1] == []:
            l.pop(len(l)-1)
        return l

    def connect(self, items_to_connect, infra):
        l = []
        for item in items_to_connect:
            l.append(Relationship(source_ref=infra, target_ref=item, relationship_type='has'))
        return l

    def create_object(self, data):
        attribs = {}
        for v in data:
            v = v.split(':')
            key = v[0]
            value = v[1]
            attribs[f'x_{self.process_key(key)}'] = self.process_key(value)

        attribs['name'] = f'processor #{attribs["x_processor"]}'

        attribs['id'] = gen_uuid('infrastructure')
        hardware = Infrastructure(**attribs, allow_custom=True)

        return hardware

    @staticmethod
    def link(src, dst, rel_type='related-to'):
        return Relationship(source_ref=src, target_ref=dst, relationship_type=rel_type)

    @staticmethod
    def process_key(text):
        text = text.lstrip().rstrip()
        text = text.replace("\t", '')
        prefix = '*-'
        if text.startswith(prefix):
            text = text[len(prefix):]
        return  text

    def characteristics(self, main_count, lines):
        l = []
        processed = 0
        next_count = self.count_prefix(lines[0])
        for index, line in enumerate(lines):
            processed += 1
            if self.count_prefix(line) == next_count:
                l.append(self.process_key(line))
            else:
                processed -= 1
                break
        return (processed, l)

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
            elif 'Characteristics' in line:
                (to_skip, l[self.process_key(line)]) = self.characteristics(self.count_prefix(line), lines[index+1:])
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
        return len(line) - len(line.lstrip('\t'))
