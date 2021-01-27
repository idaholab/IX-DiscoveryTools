from paramiko import SSHClient, AutoAddPolicy
import fabric

class RemoteConnection: #this might just be a template, we'll see if there is any use in making it a proper base class
    def __init__(self, ip, port, user=None, password=None):
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.setup()

    def connect(self):
        pass

    def runcommmand(self, command):
        pass

    def runbulk(self, commands):
        pass

    def read(self):
        pass

    def setup(self):
        pass

    def test(self, *args, **kwargs):
        return False


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
        if sudo:
            return self.client.sudo(cmd, hide=True, password=self.password)  
        else:
            return self.client.run(cmd, hide=True)  

    def listen(self):
        channel = self.client.transport.open_channel("session")
        channel.get_pty()
        channel.invoke_shell()
        return channel.recv(1048576).decode()

        # self.client.connect(self.ip, port=self.port, username=self.user, password=self.password)

    