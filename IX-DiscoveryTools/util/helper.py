#Copyright 2021, Battelle Energy Alliance, LLC
from uuid import uuid4
from stix2.datastore import Filter, FilterSet
from stix2 import Software, Process, IPv4Address, Infrastructure, Relationship, CustomExtension, properties
import logging
import re


def gen_uuid(string):
    return f'{string}--{uuid4()}'

def get_rels(stix_loader, obj, direction='in', filters=None):
        fs = FilterSet()
        if not filters is None:
            if type(filters) == list:
                for f in filters:
                    fs.add(f)
            else:
                fs.add(filters)
        if direction == 'in':
            f = Filter('target_ref', '=', obj.id)
            fs.add()
        elif direction == 'out':
            f = Filter('source_ref', '=', obj.id)
            fs.add()
        else:
            logging.error(f'Unexpected direction passed to get_rels: {direction}')

        return stix_loader.ms_source.query(fs)

def get_connected_objs(stix_loader, obj, direction='in', obj_type=None):
    f = None
    l = []

    if not obj_type is None:
        if direction == 'in':
            f = Filter('source_ref', 'contains', obj_type)
        elif direction == 'out':
            f = Filter('target_ref', 'contains', obj_type)

    rels = get_rels(stix_loader, obj, direction=direction, filters=f)

    for rel in rels:
        if direction == 'in':
            l.append(stix_loader.ms_source.get(rel.source_ref))
        elif direction == 'out':
            l.append(stix_loader.ms_source.get(rel.target_ref))
    return l

def get_connected_obj(stix_loader, obj, direction='in', obj_type=None):
    objs = get_connected_objs(stix_loader, obj, direction=direction, obj_type=obj_type)
    if len(objs) < 1:
        return None
    else:
        return objs[0]

def get_infrastructure_by_ip(stix_loader, ip):
    ip_obj = stix_loader.ms_source.query(query=Filter('value', '=', ip))[0]
    if type(ip_obj) == list and len(ip_obj) != 1:
        return None
    elif ip_obj is None:
        return None
    else:
        return get_connected_obj(stix_loader, ip_obj, direction='in', obj_type='infrastructure')

def multi_filt(op='=', **kwargs):
    fs = FilterSet()
    for key in kwargs:
        if key == 'op':
            continue
        fs.add(Filter(key, op , kwargs[key]))
    return fs

#TODO HELPER FUNCTION (param = class (software, process,etc), dictionary)
#TODO: returns created object (extensions:())
#TODO: dict.keys(startswith(x_)) key.add +'_inl'
def fix_stix(SDOType, stixdict, sdostring):
    '''
        Allows us to fix our dictionary every time we create STIX Objects to have all custom properties in an extensions list
    '''

    newList = stixdict.copy()
    extensions = {}
    for key, value in newList.items():
        if key.startswith('x_'):
            addString = key + '_inl'
            logging.debug(f'type of str: {type(addString)}')
            extensions[addString] = value
            stixdict.pop(key)
    stixdict['extensions'] = extensions
    # print(stixdict)

    # id = ''
    # print('our type: ', type(SDOType))
    # if sdostring == 'Software':
    #     id = gen_uuid('software')
    # elif sdostring == 'Infrastructure':
    #     id = gen_uuid('infrastructure')
    # elif SDOType == 'Process':
    #     id = gen_uuid('process')
    # else:
    #     print('SDO TYPE NOT INF/Software/PROCESS')

    # print(id)
    if 'id' not in stixdict.keys():
        stixdict['id'] = gen_uuid(sdostring)
    if 'allow_custom' not in stixdict.keys():
        stixdict['allow_custom'] = True
    if 'spec_version' not in stixdict.keys():
        stixdict['spec_version'] = '2.1'
    s = SDOType(**stixdict)
    return s

#Get infra connected to ip:
# - get ip by value
# - get connected by type (infra)
# - get connected by type, port, protocol, service

def get_objects(filt, stix_loader):
    objs = stix_loader.ms_source.query(filt)
    if len(objs) > 0 :
        return objs
    else:
        return None

def get_object(filt, stix_loader):
    objs = get_objects(filt, stix_loader)
    if objs is None:
        return None
    elif len(objs) == 1:
        return objs[0]
    elif len(objs) > 1:
        logging.error(f'{filt} object matched multiple objects! This could cause unexpected behavior!')
        return objs[0]

def get_related_multi(obj, filt, stix_loader):
    objs = stix_loader.ms.related_to(obj, filters=filt)
    if len(objs) > 0:
        return objs
    else:
        return None

def get_related_single(obj, filt, stix_loader):
    objs = get_related_multi(obj, filt, stix_loader)
    if objs is None:
        return None
    elif len(objs) == 1:
        return objs[0]
    elif len(objs) > 1:
        logging.error(f'{filt} object matched multiple objects! This could cause unexpected behavior!')
        return objs[0]

def get_object_or_create(ip_addr, port, protocol, service, stix_loader):
    #need to go from ip -> infra -> software (if any link is missing we need to create that link)
    # self.ms_source = self.ms.source
    # self.ms_sink = self.ms.sink
    # stix_loader.ms_source
    ret_objs = []
    ip = get_object(multi_filt(type='ipv4-addr', value=ip_addr), stix_loader)
    if ip is None:
        ip = IPv4Address(value=ip_addr)
    ret_objs.append(ip)

    infra = get_related_single(ip, multi_filt(type='infrastructure'), stix_loader)
    print(f'get_related_single_infra: {infra}')

    if infra is None:
        infra = Infrastructure(name=ip.value)
        rel = Relationship(source_ref=infra, relationship_type='has', target_ref=ip)
        ret_objs.extend([infra, rel])

    software = get_related_single(ip, multi_filt(type='software', x_port=port, x_protocol=protocol), stix_loader)
    if software is None:
        software = Software(name=f'{service if service else f"{port}/{protocol}"} Server',
        x_port=port, x_protocol=protocol, x_service=service, allow_custom=True, id=gen_uuid('software'))

        rel = Relationship(source_ref=infra, relationship_type='has', target_ref=software)
        # stix_loader.merge([software, rel])
        ret_objs.extend([software, rel])
    # ret_objs.extend([software, rel])

    return (software, ret_objs)

def get_stix_attr(obj, attr_string):
    if hasattr(obj, attr_string):
        return getattr(obj, attr_string)
    elif hasattr(obj, 'extensions'):
        if attr_string in obj.extensions:
            return obj.extensions[attr_string]
    return None
