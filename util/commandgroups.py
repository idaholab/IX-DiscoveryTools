from util.parsers import MainParser

class Command:
    def __init__(self, cmd, parser, sudo=False):
        self.cmd = cmd
        self.parser = parser
        self.sudo = sudo

    def parse(self, text):
        self.parser.parse(text)
        return []

class CommandGroup:
    def __init__(self, test_command):
        self.commands = []
        self.test_command = test_command

    def test(self):
        result = self.connector.runcommmand(self.test_command)
        if result.exited == 0:
            return True
        return False

    def add(self, cmd):
        self.commands.append(cmd)

    def run(self):
        objs = []
        for command in self.commands:
            result = self.connector.runcommmand(command.cmd, sudo=command.sudo)
            if result.exited == 0:
                print(result.stdout)
                objs.append(command.parse(result.stdout))
        return objs
        

    def register(self, connector):
        self.connector = connector

CommandGroups = []
c = CommandGroup('true')
c.add(Command('lshw', MainParser(), sudo=True))
CommandGroups.append(c)
