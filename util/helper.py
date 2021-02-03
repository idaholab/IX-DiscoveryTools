from uuid import uuid4
from stix2.datastore import Filter, FilterSet
import logging


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