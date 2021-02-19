from util.parsers import MainParser, ProcessParser, InfraParser, DMIParser, CPUInfoParser
from util.handler import Handler
import logging

class Command:
    def __init__(self, cmd, parser, sudo=False, proc_type=None):
        self.cmd = cmd
        self.parser = parser
        self.sudo = sudo
        self.proc_type = proc_type

    def parse(self, text, obj):
        return self.parser.parse(text, obj)
        

class CommandGroup:
    def __init__(self, test_command):
        self.commands = []
        self.test_command = test_command

    def test(self):
        try:
            result = self.connector.runcommmand(self.test_command)
            if result.exited == 0:
                return True
            return False
        except Exception:
            return False

    def add(self, cmd):
        self.commands.append(cmd)

    def run(self, infra_obj, types):
        objs = []
        for command in self.commands:
            if not (command.proc_type is None or command.proc_type in types):
                print('skipping')
                continue
            try:
                logging.info(f'Running: {command.cmd}')
                result = self.connector.runcommmand(command.cmd, sudo=command.sudo)
                if result.exited == 0:
                    output = result.stdout
                    if Handler.output_active:
                        Handler.OutputText(output, f'{command.cmd}.txt')
                    objs.extend(command.parse(output, infra_obj))
            except Exception as e:
                logging.warn(f'{e}')
        return objs
        
    def register(self, connector):
        self.connector = connector
CommandGroups = []
c = CommandGroup('true')
c.add(Command('lshw', MainParser(), sudo=True, proc_type='hardware'))
c.add(Command('dmidecode', DMIParser(), sudo=True, proc_type='hardware'))
# c.add(Command('cat /proc/cpuinfo', CPUInfoParser(), sudo=True, proc_type='hardware'))
c.add(Command('ps -A -l', ProcessParser(), sudo=True, proc_type='process'))
CommandGroups.append(c)
c = CommandGroup('Write-Host True')
c.add(Command('wmic process list full /format:csv', ProcessParser(delimter=','), proc_type='process'))
c.add(Command('wmic bios list /format:csv', InfraParser(delimter=',', name='BIOSInfo'), proc_type='hardware'))
c.add(Command('wmic memorychip list /format:csv', InfraParser(delimter=',', name='MemInfo'), proc_type='hardware'))
c.add(Command('wmic baseboard list /format:csv', InfraParser(delimter=',', name='BaseboardInfo'), proc_type='hardware'))
c.add(Command('wmic computersystem list /format:csv', InfraParser(delimter=',', name='ComputersystemInfo'), proc_type='hardware'))
c.add(Command('wmic cpu list /format:csv', InfraParser(delimter=',', name='CPUInfo'), proc_type='hardware'))
c.add(Command('wmic csproduct list /format:csv', InfraParser(delimter=',', name='csproductInfo'), proc_type='hardware'))
# c.add(Command('wmic bios get serialnumber', BiosParser(delimter=',', name='serialInfo')))

CommandGroups.append(c)

