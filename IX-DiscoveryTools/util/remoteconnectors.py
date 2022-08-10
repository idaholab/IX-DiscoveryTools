#Copyright 2021, Battelle Energy Alliance, LLC
from paramiko import SSHClient, AutoAddPolicy
from pypsrp.client import Client as PSClient
import logging
from telnetlib import Telnet
import fabric
from time import sleep
class result:
    def __init__(self, **kwargs): # stderr=None, stdout=None, exited=None
        for key, value in kwargs.items():
            setattr(self, key, value)

class RemoteConnection: #this might just be a template, we'll see if there is any use in making it a proper base class
    def __init__(self, ip, port, user=None, password=None):
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.setup()

class SSHConnectionParamiko(RemoteConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def setup(self):
        self.client = SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(AutoAddPolicy)
        self.transport = self.client.get_transport()

    def connect(self, ip, port):
        self.client.connect(self.ip, port=self.port, username=self.user, password=self.password)

class SSHConnectionFabric(RemoteConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def setup(self):
        self.client = fabric.Connection(self.ip,
            user=self.user, port=self.port, connect_kwargs={"password": self.password})

    def connect(self):
        self.client.open()

    def runcommmand(self, cmd, sudo=False):
        """
        Executes a command over SSH using fabric.
        """
        if sudo:
            try:
                command_obj = self.client.sudo(cmd, hide=True, password=self.password, pty=True)
                command_obj.stdout = command_obj.stdout.replace('\r', '')
                return command_obj
            except Exception as e:
                logging.exception(e)
                logging.warning('sudo failed, re-trying without!')
                return self.client.run(cmd, hide=True)
        else:
            return self.client.run(cmd, hide=True)

    def listen(self):
        """
        The listen function allows to receive data without sending anything (to capture banners).
        """
        channel = self.client.transport.open_channel("session")
        channel.get_pty()
        channel.invoke_shell()
        return channel.recv(1048576).decode()

class PSConnection(RemoteConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def setup(self):
        self.client = PSClient(self.ip, ssl=False, port=self.port, username=self.user, password=self.password)

    def connect(self):
        pass

    def runcommmand(self, cmd, sudo=None):
        stdout, stderr, had_errors = self.client.execute_ps(cmd)
        return result(stdout=stdout, stderr=stderr, exited=had_errors)

    def listen(self):
        return None

class PSConnectionSSL(PSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def connect(self):
        self.client = PSClient(self.ip, ssl=True, port=self.port, username=self.user, password=self.password)

class TelnetConnection(RemoteConnection):
    def __init__(self, *args, **kwargs):
        self.login_ran = False
        super().__init__(*args, **kwargs)


    def setup(self):
        self.client = Telnet(self.ip, self.port)
        #self.client = PSClient(self.ip, ssl=False, port=self.port, username=self.user, password=self.password)

    def connect(self):
        pass

    def login(self):
        self.client.read_until(b"login: ", timeout=5)
        self.client.write(self.user.encode('ascii') + b"\n")
        self.client.read_until(b"Password: ", timeout=5)
        self.client.write(self.password.encode('ascii') + b"\n")
        sleep(5)
        self.client.read_very_eager().decode('ascii')

    def runcommmand(self, cmd, sudo=None):
        if not self.login_ran:
            self.login()
            self.login_ran = True

        self.client.write(cmd.encode('ascii') + b"\n")
        sleep(8)
        stdout = self.client.read_very_eager().decode('ascii')
        if 'not found' in stdout or 'Permission denied' in stdout:
            exited = 1
        else:
            exited = 0
        stdout = stdout.split('\n', maxsplit=1)[1]
        stdout = stdout.rsplit('\n', maxsplit=1)[0]
        stdout = stdout.replace('\r', '')
        return result(stdout=stdout, stderr='', exited=exited)

    def listen(self):
        return None
