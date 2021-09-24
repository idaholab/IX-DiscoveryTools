#Copyright 2021, Battelle Energy Alliance, LLC
from datetime import datetime
import os
import pyshark
import logging
from tempfile import mkdtemp
from multiprocessing import Process, Manager
from time import sleep
import shutil
import logging

def worker(cap, manager):
    for _ in cap.sniff_continuously():
        if manager['done']:
            break

class OutputHandler:
    def __init__(self):
        self.starttime = datetime.now()
        self.output_active = False
        self.logging_active = False
        self.stix_loader = False
        self.counter = 1
        self.base_dir = 'data'

    def dealdatadir(self):
        if not os.path.exists(self.base_dir):
            os.mkdir(self.base_dir)

    def registerSTIXLoader(self, sl):
        self.sl = sl
        self.stix_loader = True

    def registerLogger(self):
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        fileHandler = logging.FileHandler(os.path.join(self.dir, 'log.txt'))
        fileHandler.setLevel(logging.INFO)
        logger.addHandler(fileHandler)
        self.logging_active = True

    def registerOutputDir(self, dir):
        self.dealdatadir()
        self.dir_basename = dir
        self.dir = os.path.join(self.base_dir, dir)

        if not os.path.exists(self.dir):
            os.mkdir(self.dir)

        self.output_active = True

    def OutputText(self, text, filename):
        filename = filename.replace(' ', '_').replace('-', '_').replace(':', '_').replace('/', '_') # this is terrible
        with open(os.path.join(self.dir, filename), 'w') as f:
            f.write(text)

    def startPCAP(self, interface='ens33'):
        try:
            self.f = mkdtemp()
            self.pcap_path = os.path.join(self.f, 'capture.pcap')
            self.cap = pyshark.LiveCapture(output_file=self.pcap_path , interface=interface, custom_parameters={'-B': '10000' })
            manager = Manager()
            self.done = manager.dict({'done': False})
            self.t = Process(target=worker, args=(self.cap, self.done))
            self.t.start()
            sleep(5)
        except Exception as e:
            logging.error('Failed to start PCAP capture process, there will likely not be a pcap!')
            logging.exception(e)


    def stopPCAP(self):
        try:
            self.cap.close()
            self.done['done'] = True
            sleep(10)
            self.t.terminate()
            shutil.copy(self.pcap_path, os.path.join(self.dir, 'capture.pcap'))
            os.remove(self.pcap_path)
        except Exception as e:
            logging.error('Failed to stop PCAP capture process, there will likely not be a pcap!')
            logging.exception(e)

    def writeMetadata(self):
        endtime = datetime.now()
        text = f'{self.starttime.strftime("%Y-%m-%d %H:%M:%S %Z")}\n{endtime.strftime("%Y-%m-%d %H:%M:%S %Z")}'
        self.OutputText(text, 'metadata.txt')

    def finish(self):
        if self.cap:
            self.stopPCAP()
        self.writeMetadata()
        self.stixoutput(name=self.dir_basename)
        shutil.rmtree(self.f)

    def stixoutput(self, name=None):
        if not self.stix_loader:
            return None
        if name is None:
            path_name = f'merge{self.counter}.json'
            self.counter += 1
        else:
            path_name = f'{name}.json'
        self.sl.write_out(os.path.join(self.dir, path_name))

Handler = OutputHandler()
