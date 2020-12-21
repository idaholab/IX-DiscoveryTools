class stix_loader:
    def __init__(self, in_file=None):
        self.in_file = in_file


        if self.in_file is not None:
            self.read_in()
        else:
            self.create_blank()

    def read_in(self):
        pass

    def create_blank(self):
        pass

    def write_out(self, path):
        pass