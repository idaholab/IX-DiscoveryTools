#Copyright 2021, Battelle Energy Alliance, LLC
import pyshark
import logging
from stix2 import Infrastructure, IPv4Address, Relationship, Software, NetworkTraffic, CustomExtension, properties
from stix2.datastore import Filter, FilterSet
from autodiscover.util.helper import gen_uuid, multi_filt, get_stix_attr, get_object_or_create
from tqdm import tqdm
import operator

def packet_obj(protocol, service, src, dst):
    return NetworkTraffic(id=gen_uuid('network-traffic'), #name=f'{service if service else protocol} traffic',
    protocols=[protocol, service] if service else [protocol],
    src_ref=src, dst_ref=dst)

def get_other_ip(packet, ip):
    newobj_ip = None
    newobj_port = None

    if ip != packet.ip.src and ip == packet.ip.dst:
        newobj_ip = packet.ip.src
        if hasattr(packet, 'tcp'):
            newobj_port = packet.tcp.srcport
        elif hasattr(packet, 'udp'):
            newobj_port = packet.tcp.srcport
    elif ip != packet.ip.dst and ip == packet.ip.src:
        newobj_ip = packet.ip.dst
        if hasattr(packet, 'tcp'):
            newobj_port = packet.tcp.dstport
        elif hasattr(packet, 'udp'):
            newobj_port = packet.tcp.dstport
    else:
        logging.error('Packet src: {packet.ip.src}, dst: {packet.ip.dst}, {ip} should be in exactly one field')

    return (newobj_ip, newobj_port)


class pcap:
    def __init__ (self, args, stix_loader, file=None):
        if file is None:
            logging.warning('There is no input pcap, the pcap plugin will do nothing...')
        self.args = args
        self.stix_loader = stix_loader
        self.file = file
        self.sink = self.stix_loader.ms_sink
        self.source = self.stix_loader.ms_source

    def run(self):
        l = []
        logging.info('running pcap plugin')
        #we need to get a list of ip objects:
        ip_objs = self.source.query(Filter('type', '=','ipv4-addr'))
        logging.debug(ip_objs)
        #follow back to infra object
        d = {}
        for ip_obj in tqdm(ip_objs, desc='Processing IP objs', total=len(ip_objs), position=1):

            rels = self.source.query(Filter('target_ref', '=', ip_obj.id))
            if len(rels) == 1:
                d[ip_obj.value] = []
                infra = self.source.get(rels[0].source_ref)
                #then out to software objects, compile list of proto/ports

                fs = FilterSet()
                fs.add(Filter('source_ref', '=', infra.id))
                fs.add(Filter('target_ref', 'contains', 'software'))

                rels = self.source.query(fs)
                softwares = [self.source.get(rel.target_ref) for rel in rels]

                #TASK #7 subtaxk 4 will require this to be different.
                #instead of checking x_ attribute we check the json array of 'extensions'

                

                for software in tqdm(softwares, desc='Processing software objs', total=len(softwares), position=0):
                    print(f'software: {software}')
                    port = get_stix_attr(software, 'x_port_inl')
                    protocol = get_stix_attr(software, 'x_protocol_inl')
                    service = get_stix_attr(software, 'x_service_inl')
                    print(port, protocol, service)
                    if port is not None and protocol is not None:
                        d[ip_obj.value].append((port, protocol, service, software))

                # for software in tqdm(softwares, desc='Processing software objs', total=len(softwares), position=1):
                #     print(f'software: {software}')
                #     if hasattr(software, 'x_port_inl') and hasattr(software, 'x_protocol_inl'):
                #         if hasattr(software, 'x_service_inl'):
                #             d[ip_obj.value].append((software.x_port, software.x_protocol_inl, software.x_service_inl, software))
                #         else:
                #             d[ip_obj.value].append((software.x_port, software.x_protocol_inl, None, software))
        print(f'dict: {d}')
        #search pcap for ip/proto[tcp/udp]/port combinations
        if not self.file is None:
            if self.get_packet('') is None:
                logging.error(f'No packets in file {self.file} or file cannot be accessed...')
                return None
            for ip in tqdm(d, desc='Finding connections by ip', total=len(d), position=0):
                for port_proto in tqdm(d[ip], desc='Finding connections by port_proto', total=len(d[ip]), position=1):
                    logging.debug(f'Evaluating {port_proto}')
                    packet = None
                    (port, protocol, service, src_software) = port_proto
                    if port_proto[2]:
                        filt = f'ip.addr == {ip} and {protocol}.port == {port} and {protocol} and {service}'
                        logging.debug(f'Filter {filt}')
                        packet = self.get_packet(filt)

                    if packet is None:
                        filt = f'ip.addr == {ip} and {protocol}.port == {port} and {protocol}'
                        packet = self.get_packet(filt)

                    if not packet is None:
                        logging.debug(f'Matching packet: {packet}')
                        (newobj_ip, newobj_port) = get_other_ip(packet, ip)

                        if newobj_ip:
                            (software, ret_objs) = self.get_object_or_create(newobj_ip, newobj_port, protocol, service)

                            net_traffic = packet_obj(protocol, service,
                            self.source.query(Filter('value', '=', newobj_ip))[0],
                            self.source.query(Filter('value', '=', ip))[0],)
                            print(f'target_ref: {software}')
                            l.append(Relationship(source_ref=net_traffic, relationship_type='uses', target_ref=software))
                            l.append(Relationship(source_ref=software, relationship_type='uses', target_ref=net_traffic))
                            l.append(Relationship(source_ref=net_traffic, relationship_type='uses', target_ref=src_software))
                            l.append(Relationship(source_ref=src_software, relationship_type='uses', target_ref=net_traffic))
                            l.append(net_traffic)

                            l.extend(ret_objs)


            # for the moment we need to make sure the other ip address is in our list as well
                #Could always do crazy mode here as well.
        #create network traffic object to hold an example

        # one for each direction
        #   then we can always try crazy mode were we make one for each match
        else:
            logging.error('Pcap plugin is running, but no input file is given...')
        self.stix_loader.merge(l)
        logging.info('finishing pcap plugin')

    def get_packet(self, filt):
        
        try:
            logging.debug('creating capture')
            cap = pyshark.FileCapture(self.file, display_filter=filt, keep_packets=False)
            logging.debug('loading packets')
            cap.load_packets(packet_count=1)
            logging.debug('grabbing first')
            packet = cap.next()
        except StopIteration:
            packet = None
        except pyshark.capture.capture.TSharkCrashException:
            return None
        finally:
            logging.debug('closing capture')
            try:
                cap.close()
            except:
                pass
        

        # if cap.__len__() > 0:
        #     packet = cap[0]
        # else:
        #     packet = None
        # cap.close()
        logging.debug('returning first')
        logging.debug(f'packet value: {packet}')
        return packet


    def get_object_or_create(self, ip, port, protocol, service):
        return get_object_or_create(ip, port, protocol, service, self.stix_loader)
    # #TODO: task # 7 subtaxk 4 isntead of x_ attribute we save extensions..
    # def get_object_or_create(self, ip, port, protocol, service):
    #     #need to go from ip -> object -> software (if any link is missing we need to create that link)
    #     fs = multi_filt(type='ipv4-addr', value=ip)
    #     objs = self.source.query(fs)
    #     if len(objs) == 0:
    #         ip = IPv4Address(value=ip)
    #         self.stix_loader.merge([ip])
    #     else:
    #         if len(objs) > 1:
    #             logging.error(f'{ip.value} object is duplicated! This could cause unexpected behavior!')
    #         ip = objs[0]

    #     fs = multi_filt(type='relationship', target_ref=ip.id)
    #     objs = self.source.query(fs)

    #     if len(objs) == 0:
    #         infra = Infrastructure(name=ip.value)
    #         rel = Relationship(source_ref=infra, relationship_type='has', target_ref=ip)
    #         self.stix_loader.merge([infra, rel])
    #     else:
    #         if len(objs) > 1:
    #             logging.error(f'Relationship from {ip.id} to infra is duplicated! This could cause unexpected behavior!')
    #         rel = objs[0]
    #         infra = self.source.get(rel.source_ref)

    #     fs = multi_filt(type='relationship', source_ref=infra.id)
    #     fs.add(Filter('target_ref', 'contains', infra.id))
    #     objs = self.source.query(fs)


    #     software = None
    #     # @CustomExtension(Software, 'x_software_extensions_INL', [
    #     #     ('x_port_INL', properties.IntegerProperty()),
    #     #     ('x_protocol_INL', properties.StringProprety(required=True)),
    #     #     ('x_service_INL', properties.StringProperty(required=True))])
    #     # class NewExtension():
    #     #     pass

    #     if len(objs) > 0:
    #         for obj in objs:
    #             #TODO Task 7, subtask 4 CHECK THIS THING
    #             extensions = NewExtension(x_port_INL=port, x_protocol_INL=protocol, x_service_INL=service)
    #             fs = multi_filt(extensions=extensions, id=obj.target_ref)
    #             # fs = multi_filt(x_port=port, x_protocol=protocol, id=obj.target_ref)
    #             softwares = self.source.query(fs)
    #             if len(softwares) > 0:
    #                 software = softwares[0]
    #                 break

    #     if software is None:
    #         # software = Software(name=f'{service if service else f"{port}/{protocol}"} Client',
    #         # x_port=port, x_protocol=protocol, x_service=service, allow_custom=True, id=gen_uuid('software'))

    #         extensions = NewExtension(x_port_INL=port, x_protocol_INL=protocol, x_service_INL=service)
    #         software = Software(name=f'{service if service else f"{port}/{protocol}"} Client',
    #         extensions=extensions, allow_custom=True, id=gen_uuid('software'))

    #         rel = Relationship(source_ref=infra, relationship_type='has', target_ref=software)
    #         self.stix_loader.merge([software, rel])



    #     return software
