#Copyright 2021, Battelle Energy Alliance, LLC
import xml.etree.ElementTree as ET
from stix2 import Vulnerability, Infrastructure, CourseOfAction, Relationship, IPv4Address, Bundle
from gvm.xml import pretty_print
import sys, os
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from autodiscover.util.helper import fix_stix, get_object_or_create

# Create python etree

def parse_bundle(root, stix_loader):

    # Create and open file a
    # f = open('latest_test.json', 'w')

    objs = []
    # host/port
    # Create infrastructure object
    i_name = root.find('./task/name').text
    # print(i_name)
    d = {'spec_version': '2.1', 'name': i_name}
    # infra = Infrastructure, d)
    # infra = fix_stix(Infrastructure, d, 'infrastructure')
    # objs.append(infra)

    count = 0
    ip_addr = None

    # Loop through vulns
    for r in root.findall("./results/result"):
        # print(ET.tostring(r,encoding='unicode'))
        
        # Ip address
        count += 1
        if ip_addr is None:
            value = r.find('host').text
            ip_addr = value
        #     # ip = IPv4Address(value = value)
        #     ip = fix_stix(IPv4Address, {'value': value}, 'ipv4-addr')
        #     infra_to_ip = Relationship(custom_properties={'spec_version': '2.1'}, source_ref = infra.id,
        #                                         target_ref = ip.id, relationship_type = 'has')
        #     objs.append(ip)
        #     objs.append(infra_to_ip)

        # Vulnerabilities
        d = {}
        d['spec_version'] = '2.1'
        d['name'] = r.find('name').text
        d['description'] = r.find('description').text
        d['x_cvss_score'] = r.find('nvt/cvss_base').text
        d['x_host'] = r.find('host').text
        d['x_port'] = r.find('port').text
        d['x_qod'] = r.find('qod/value').text
        ex_refs = [] # external references
        for ref in r.findall("nvt/refs/ref"):
            src = ref.get('type')
            rid = ref.get('id')
            ex_ref = {}

            if src == 'url':
                ex_ref = {"url": rid, "source_name": rid}

            else:
                ex_ref = {"source_name": src, "external_id": rid}
            ex_refs.append(ex_ref)
        d['external_references'] = ex_refs

        # vuln = Vulnerability(**d)
        vuln = fix_stix(Vulnerability, d, 'vulnerability')
        objs.append(vuln)


        # Courses of Action
        c_name = r.find('nvt/solution').text
        # print(c_name)
        if c_name is not None:
            d = {'spec_version': '2.1', 'name': f'Mitigation - {vuln.name}', 'description': c_name}
            coa = fix_stix(CourseOfAction, d, 'course-of-action')
            # coa = CourseOfAction(custom_properties={'spec_version': '2.1'}, ,
                                                # description = c_name)
            objs.append(coa)

            coa_to_v = Relationship(custom_properties={'spec_version': '2.1'}, source_ref = coa.id,
                                                    target_ref = vuln.id, relationship_type = 'mitigates')
            objs.append(coa_to_v)

    # Relationships
        port_proto = r.find('port').text
        port_proto_split = port_proto.split('/')
        if len(port_proto_split) == 2:
            port = port_proto_split[0]
            protocol = port_proto_split[1]
        else:
            port = port_proto
            protocol = port_proto

        software, ret_objs = get_object_or_create(ip_addr, port, protocol, None, stix_loader)
        stix_loader.quiet_merge(ret_objs)
        infra_to_software = Relationship(custom_properties={'spec_version': '2.1'}, source_ref = software.id,
                                                target_ref = vuln.id, relationship_type = 'has')
        # infra_to_vuln = Relationship(custom_properties={'spec_version': '2.1'}, source_ref = infra.id,
        #                                         target_ref = vuln.id, relationship_type = 'has')
        objs.extend(ret_objs)
        objs.append(infra_to_software)

        # These have been moved to the respective objects as they may not always be present for each vuln.
        # Add to bundle

        # objs.append(vuln)
        # objs.append(coa)
        # objs.append(coa_to_v)
        # objs.append(infra_to_vuln)

    # Create Bundle
    # bundle = Bundle(objs)
    # print('writing...')

    # Write to file
    # f.write(str(bundle))

    print('done')
    print('count: ', count)
    # f.close()
    return objs

if __name__ == '__main__':
    tree = ET.parse('odroid-xu4-gvm-report.xml')
    root = tree.getroot()
    parse_bundle(root)
