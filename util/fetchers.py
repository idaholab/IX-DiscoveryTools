import csv
class CSVFetcher:
    def __init__(self, csv_path):
        with open(csv_path) as f:
            c = csv.DictReader(f)
            self.rows = [row for row in c]

    def get_targets(self):
        return [(row['ip'], row['port']) for row in self.rows]

    def get_creds(self, ip, port):
        for row in self.rows:
            if row['ip'] == ip and row['port'] == port:
                return (row['username'], row['password'])

class STIXFetcher:
    def __init__(self, stix_loader):
        pass

class InputFetcher:
    def __init__(self):
        pass
