#Copyright 2021, Battelle Energy Alliance, LLC
import sys
import time
from gvm.connections import TLSConnection
from gvm.errors import GvmError, GvmResponseError
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv208 import CredentialType, AliveTest
from gvm.transforms import EtreeCheckCommandTransform
from gvm.xml import pretty_print
from pprint import pprint
from uuid import uuid4
import socket
import logging

class CouldNotConnectToScanner(Exception):
    pass

def report_tester(function):
    scan_status = function.find('./report/report/scan_run_status')
    if scan_status.tag == 'scan_run_status':
        if scan_status.text == 'Requested':
            print("\r[+] Scan is Requested... ", end =" ")
        if scan_status.text == 'Queued':
            print("\r[+] Scan is Queued... ", end = " ")
        if scan_status.text == 'Running':
            print("\r[+] Scan is Running... ", end = " ")
        if scan_status.text == 'Done':
            print("\r[+] Scan is Done ", end = " ")
            return True

def run_scan(system_login='msfadmin', system_password='msfadmin',  username='admin', password='admin', host='192.168.27.2'):
    try:
        tasks = []
        connection = TLSConnection()
        transform = EtreeCheckCommandTransform()

        counter = 0
        while True:

            try:
                Gmp(connection=connection, transform=transform)
                break
            except:
                logging.info('Failed to connect to openvas, retrying...')
                time.sleep(5)
                counter += 1
                if counter == 6:
                    break
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(username, password)

            target_name = 'OpenVAS Default'
            scanners = gmp.get_scanners()

            logging.info("Scanner ID")
            for name in scanners:
                if name.tag == 'scanner':
                    for element in name:
                        if element.tag == 'name' and element.text == target_name:
                            logging.info(name.attrib['id'])
                            scanner_id = str(name.attrib['id'])


            try:
                credential_response = gmp.create_credential(name=f'{system_login}-{system_password}',
                                                            credential_type=CredentialType.USERNAME_PASSWORD,
                                                            login=system_login, password=system_password)
            except:
                logging.info("Credential exist already")

            credentials = gmp.get_credentials()
            #credentials.find(f'./credential/[.="{system_login}-{system_password}"]..').attrib['id']
            logging.info("\n Credential ID")
            for name in credentials:
                if name.tag == 'credential':
                    for element in name:
                        if element.text == f'{system_login}-{system_password}':
                            logging.info(name.attrib['id'])
                            credential = str(name.attrib['id'])

            hosts = [host]
            ssh_credential_id = credential

            target_port_list = 'All IANA assigned TCP'
            port_list_response = gmp.get_port_lists()

            port_list_id = port_list_response.find('./port_list/name[.="All IANA assigned TCP"]..').attrib['id']
            target_name = f'{host.replace(".","-")}{port_list_id}{ssh_credential_id}'

            try:
                create_target = gmp.create_target(name=target_name, hosts=hosts, ssh_credential_id=ssh_credential_id,
                                                  port_list_id =port_list_id, alive_test=AliveTest.CONSIDER_ALIVE)  # ssh_credential_port=ssh_credential_port
            except Exception as e:
                logging.exception(e)
                logging.info("Credential Already Exists")

            targets = gmp.get_targets()
            logging.info("\n Target ID")
            for name in targets:
                if name.tag == 'target':
                    for element in name:
                        if element.text == target_name:
                            logging.info(name.attrib['id'])
                            target_id = str(name.attrib['id'])

            configs = gmp.get_scan_configs()

            logging.info("\n Config ID")
            for name in configs:
                if name.tag == 'config':
                    for element in name:
                        if element.tag == 'name' and element.text == "Full and fast":
                            logging.info(name.attrib['id'])
                            config_id = str(name.attrib['id'])

            config_id = config_id
            target_id = target_id
            scanner_id = scanner_id
            task_name = f"{str(host).replace('.', '-')}-{uuid4()}"
            create_task = gmp.create_task(name=str(task_name), config_id=config_id, target_id=target_id,
                                              scanner_id=scanner_id)
            get_task = gmp.get_tasks(filter_string=f'name~{task_name}')
            logging.info("\n Task ID")
            task_id = get_task.find(f'./task/name[.="{task_name}"]..').attrib['id']
            # for name in get_task:
            #     if name.tag == 'task':
            #         for element in name:
            #             if element.tag == 'name' and element.text == task_name:
            #                 logging.info(str(task_name) + ": " + name.attrib['id'])
            #                 task_id = str(name.attrib['id'])
            start_task = gmp.start_task(task_id)
            report_id = start_task.find('report_id').text

            print("[+] Status of Scan\n[+]")
            try:
                while True:
                    try:
                        if not gmp.is_authenticated():
                            gmp.authenticate(username, password)
                        time.sleep(3)
                        get_reports = gmp.get_report(report_id = report_id)
                        pretty_print(get_reports)
                        if report_tester(get_reports):
                            break

                    except Exception as e:
                        pass

            except Exception as e:
                logging.info("\n[+] Generating Report...Please...Wait")
                logging.exception(e)
                time.sleep(3)

            if not gmp.is_authenticated():
                gmp.authenticate(username, password)
            
            get_reports = gmp.get_report(report_id = report_id, details=True, ignore_pagination=True)
            error_desc = get_reports.find('./report/report/errors/error/description')
            if error_desc is not None and error_desc.text == 'Could not connect to Scanner':
                raise CouldNotConnectToScanner
            logging.info("Your XML Output is: ")
            report = get_reports.find('./report/report')
            return report


    except GvmError as e:
        logging.exception(f'An error occurred: {e}')
