from datetime import datetime
import os
import pyshark
import logging
class OutputHandler:
    def __init__(self):
        self.starttime = datetime.now()
        self.output_active = False
        self.logging_active = False
        self.stix_loader = False
        self.counter = 1

    def dealdatadir(self):
        if not os.path.exists('data'):
            os.mkdir('data')

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
        self.dir = os.path.join('data', dir)

        if not os.path.exists(self.dir):
            os.mkdir(self.dir)

        self.output_active = True
    
    def OutputText(self, text, filename):
        filename = filename.replace(' ', '_').replace('-', '_').replace(':', '_') # this is terrible
        with open(os.path.join(self.dir, filename), 'w') as f:
            f.write(text)

    def startPCAP(self, interface='ens33'):
        pass
        # pcap_path = os.path.join(self.dir, 'capture.pcap')
        # cap = pyshark.LiveCapture(output_file=pcap_path, interface=interface)
        # for packet in cap.sniff_continuously(packet_count=1):
        #     print(packet)
        # cap.close()

    def stopPCAP(self):
        pass

    def writeMetadata(self):
        endtime = datetime.now()
        text = f'{self.starttime.strftime("%Y-%m-%d %H:%M:%S %Z")}\n{endtime.strftime("%Y-%m-%d %H:%M:%S %Z")}'
        self.OutputText(text, 'metadata.txt')

    def finish(self):
        self.stopPCAP()
        self.writeMetadata()
        self.stixoutput(name=self.dir)

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


