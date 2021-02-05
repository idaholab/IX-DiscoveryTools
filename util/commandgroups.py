from util.parsers import MainParser, ProcessParser, InfraParser
from util.handler import Handler

class Command:
    def __init__(self, cmd, parser, sudo=False):
        self.cmd = cmd
        self.parser = parser
        self.sudo = sudo

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

    def run(self, infra_obj):
        objs = []
        for command in self.commands:
            result = self.connector.runcommmand(command.cmd, sudo=command.sudo)
            if result.exited == 0:
                output = result.stdout
                if Handler.output_active:
                    Handler.OutputText(output, f'{command.cmd}.txt')
                objs.extend(command.parse(output, infra_obj))
        return objs
        
    def register(self, connector):
        self.connector = connector
CommandGroups = []
c = CommandGroup('true')
c.add(Command('lshw', MainParser(), sudo=True))
c.add(Command('ps -A -l', ProcessParser(), sudo=True))
CommandGroups.append(c)
c = CommandGroup('Write-Host True')
c.add(Command('wmic process list full /format:csv', ProcessParser(delimter=',')))
c.add(Command('wmic bios list /format:csv', InfraParser(delimter=',', name='BIOSInfo')))
c.add(Command('wmic memorychip list /format:csv', InfraParser(delimter=',', name='MemInfo')))
c.add(Command('wmic baseboard list /format:csv', InfraParser(delimter=',', name='BaseboardInfo')))
c.add(Command('wmic computersystem list /format:csv', InfraParser(delimter=',', name='ComputersystemInfo')))
c.add(Command('wmic cpu list /format:csv', InfraParser(delimter=',', name='CPUInfo')))
c.add(Command('wmic csproduct list /format:csv', InfraParser(delimter=',', name='csproductInfo')))
# c.add(Command('wmic bios get serialnumber', BiosParser(delimter=',', name='serialInfo')))

CommandGroups.append(c)

