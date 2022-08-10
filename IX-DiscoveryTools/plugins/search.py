#Copyright 2021, Battelle Energy Alliance, LLC
import json
import re
import os
import argparse
import requests
import logging
from pprint import pprint
from packaging.version import LegacyVersion
from bs4 import BeautifulSoup
from zipfile import ZipFile
from shutil import rmtree
from dateutil.parser import parse
from io import BytesIO
from glob import glob
from tqdm import tqdm
from multiprocessing import Pool, Manager
from functools import partial
from stix2 import Vulnerability, ExternalReference


def download_zip(src_url, dst):
    r = requests.get(src_url, allow_redirects=True)
    with ZipFile(BytesIO(r.content)) as z:
        with z.open(z.namelist()[0]) as f:
            open(dst, 'wb').write(f.read())
    #data_to_write = ZipFile(BytesIO(r.content))
    #open(dst, 'wb').write(data_to_write)

def download_text(src_url):
    r = requests.get(src_url, allow_redirects=True)
    return r.text

def prune_to_year(string):
    s = string.split('/')[-1]
    s = s.replace('.meta', '')
    s = s.replace('.json.zip', '')
    s = s.replace('nvdcve-1.1-', '')
    return s

class CVE:
    def __init__(self, data=None):
        self.data = data
        if self.data is not None:
            self.decode()

    def decode(self):

        self.id = self.data['cve']['CVE_data_meta']['ID']
        self.filters = self._decode(self.data['configurations'])
        self.description = self.get_en_description()
        self.references = self.gen_references() # dict with source_name, url
        self.publishedDate = self.data['publishedDate']
        self.lastModifiedDate = self.data['lastModifiedDate']
        self.cvssV3 = self.gen_cvssV3()
        self.cvssV2 = self.gen_cvssV2()

    def gen_cvssV3(self):
        try:
            return self.data['impact']['baseMetricV3']['cvssV3']
        except Exception:
            return None

    def gen_cvssV2(self):
        try:
            return self.data['impact']['baseMetricV2']['cvssV2']
        except Exception:
            return None

    def get_en_description(self):
        for item in self.data['cve']['description']['description_data']:
            if item['lang'] == 'en':
                return item['value']

    def gen_references(self):
        l = []
        for item in self.data['cve']['references']['reference_data']:
            d = {}
            if 'url' in item:
                d['url'] = item['url']
            if 'name' in item:
                d['source_name'] = item['name']
            l.append(d)
        return l

    def to_external_references(self):
        l = []
        for reference in self.references:
            l.append(ExternalReference(**reference))
        return l


    def to_stix(self):
        return Vulnerability(name=self.id,
        description=self.description,
        external_references=self.to_external_references(),
        cvssV3=self.cvssV3,
        cvssV2=self.cvssV2, allow_custom=True
        )

    def _decode(self, data):
            # print('decode data: ', data)
            l = []
            if ('children' in data.keys() and len(data['children']) > 0) or ('nodes' in data.keys() and len(data['nodes']) > 0):
                if 'nodes' in data.keys():
                    items = data['nodes']
                elif 'children' in data.keys():
                    items = data['children']
                for item in items:
                    l.append(self._decode(item))
            elif 'cpe_match' in data.keys():
                for cpe_match in data['cpe_match']:
                    # print('Trying CPE Match: ', cpe_match)
                    c = cpe(cpe_match)
                    l.append(c)
            try:
                return {data['operator']: l}
            except:
                if l == []:
                    return None
                else:
                    return {"OR": l}


    def match(self,**kwargs):
        if self.filters is None:
            return None
        a = self._match(self.filters, **kwargs)
        return a

    def _match(self, f, **kwargs):
        if 'AND' in f.keys():
            return self._match_and(f['AND'], **kwargs)
        elif 'OR' in f.keys():
            return self._match_or(f['OR'], **kwargs)

    def _match_and(self, data, **kwargs):
        return self._match_or(data, **kwargs)

    def _match_or(self, data, **kwargs):
        cond = None
        for d in data:
            if isinstance(d, dict):
                cond = self._or(cond, self._match(d, **kwargs))
            elif isinstance(d, cpe):
                cond = self._or(cond, d.match(**kwargs))
        return cond

    def _and(self, a, b):
        if a is None:
            return b
        elif b is None:
            return a
        else:
            return a and b

    def _or(self, a, b):
        if a is None:
            return b
        elif b is None:
            return a
        else:
            return a or b


class cpe:
    #PASS IN CPE?
    def __init__(self, data=None):
        self.data = data

        if self.data is not None:
            self.decode()

    def decode(self):
        #data = string.split(':')

        #need to unescape the escape character first
        self.vulnerable = self.data['vulnerable']

        if 'cpe22Uri' in self.data.keys():
            logging.debug('we need to fix this')
        string = self.data['cpe23Uri']


        self.filters = {}
        for filt in ['versionStartIncluding','versionStartExcluding','versionEndIncluding','versionEndExcluding']:
            if filt in self.data.keys():
                self.filters[filt] = self.data[filt]

        string = string.replace('\\\\', '\\')
        data = re.split(r'(?<!\\):', string)
        #we need to pad the list for the next part
        data += [None] * (13 - len(data))

        # print(self.data)
        (self.cpe,
        self.cpe_version,
        self.part,
        self.vendor,
        self.product,
        self.version,
        self.update,
        self.edition,
        self.language,
        self.sw_edition,
        self.target_sw,
        self.target_hw,
        self.other) = data

    def _regex_version_range(self, **kwargs):
        for val in self.filters:
            if re.fullmatch(kwargs['version'],self.filters[val], flags=re.IGNORECASE) is None:
                return False
        return True

    def match(self,**kwargs):
        for item in kwargs:
            if kwargs[item] == None:
                # if item == 'version':
                #     return False
                continue
            
            if item == 'version':
                if self._regex_version_range(**kwargs):
                    pass
                else:
                    if 'versionStartIncluding' in self.filters.keys():
                        if LegacyVersion(self.filters['versionStartIncluding']) > LegacyVersion(kwargs[item]):
                            return False
                    elif 'versionStartExcluding' in self.filters.keys():
                        if LegacyVersion(self.filters['versionStartExcluding']) >= LegacyVersion(kwargs[item]):
                            return False
                    if 'versionEndIncluding' in self.filters.keys():
                        if LegacyVersion(self.filters['versionEndIncluding']) < LegacyVersion(kwargs[item]):
                            return False
                    elif 'versionEndExcluding' in self.filters.keys():
                        if LegacyVersion(self.filters['versionEndExcluding']) <= LegacyVersion(kwargs[item]):
                            return False
            elif kwargs[item] is None:
                continue
            try:
                if item == 'cpe':
                    if kwargs['cpe'] in self.data['cpe23Uri']:
                        return True
            except Exception as e:
                        logging.exception(e)

            try:
                if item != 'version' and (getattr(self, item) == '*'):
                    continue
                elif item == 'version' and getattr(self,item, False) == False:
                    #require version to be populated
                    continue
                elif re.fullmatch(kwargs[item], getattr(self, item), flags=re.IGNORECASE) is None:
                    return False
            except TypeError as ty:
                logging.info('TypeError %s', ty)

        return True

class cve_searcher:
    def __init__(self, proc_num=4):
        self.proc_num = proc_num
        self.base_url = 'https://nvd.nist.gov'
        self.my_dir = os.path.dirname(__file__)
        self.data_dir = os.path.join(self.my_dir, 'cve_data')
        self.db_file = os.path.join(self.data_dir, 'db.json')

        if not self.check_if_loaded():
            self._init_dirs()
            self.init_db()
            self.load()
        self.data_files = self.get_data_files()

    def check_if_loaded(self):
        if os.path.isdir(self.data_dir):
            return True
        return False

    def load(self):
        self.get_file_urls()
        self.download_all()

    def download_all(self):
        for entry in self.zip_dict:
            text = download_text(f'{self.base_url}{self.meta_dict[entry]}')
            text = text.split('\n')
            d = {}
            for item in text:
                item = item.split(':')
                if item[0] == 'lastModifiedDate' or item[0] == 'sha256':
                    d[item[0]] = item[1]
            self.update_db(entry, d)
            download_zip(f'{self.base_url}{self.zip_dict[entry]}',
                os.path.join(self.data_dir,
                    f'{prune_to_year(self.zip_dict[entry])}.json'))

    def clean(self):
        try:
            rmtree(self.data_dir)
        except Exception as e:
            logging.exception(e)

    def init_db(self):
        with open(self.db_file, 'w') as f:
            json.dump({}, f)

    def update_db(self, entry, d):
        data = self.get_db()
        data[entry] = d
        with open(self.db_file, 'w') as f:
            json.dump(data, f)

    def get_db(self):
        with open(self.db_file, 'r') as f:
            data = json.load(f)
        return data

    def get_file_urls(self):
        url = 'https://nvd.nist.gov/vuln/data-feeds'
        r = requests.get(url)
        soup = BeautifulSoup(r.text, features="html.parser")
        a = soup.find(lambda x: x.name == 'a' and 'NVD JSON' in str(x.string))
        table = a.parent.parent.parent.parent
        self.meta_dict = {}
        self.zip_dict = {}
        links = table.find_all('a')
        for link in links:
            if '.meta' in link['href']:
                l = link['href']
                self.meta_dict[prune_to_year(l)] = l
            elif '.zip' in link['href']:
                l = link['href']
                self.zip_dict[prune_to_year(l)] = l

    def get_data_files(self):
        g = glob(os.path.join(self.data_dir, '*'))
        new_g = []
        for f in g:
            if 'modified' in f or 'db' in f or 'recent' in f:
                continue
            new_g.append(f)
        return new_g

    def update(self):
        pass

    def worker(self, func):
        return func()

    def search_file(self, data_file, **kwargs):
        vuln_cves = []
        logging.debug('trying to match')
        logging.debug(f'against kwargs: {kwargs}')
        with open(data_file) as f:
            json_data = json.load(f)

        cves = []
        for elem in json_data['CVE_Items']:
            cves.append(CVE(elem))

        for cve in cves:
            if cve.match(**kwargs):
                vuln_cves.append(cve)

        return vuln_cves

    def search_pass(self, **kwargs):
        self.cpe_pass_through = kwargs['cpe']

        self.cpe = self.cpe_pass_through[0]
        self.cpe_version = self.cpe_pass_through[1]
        self.part = self.cpe_pass_through[2]
        self.vendor = self.cpe_pass_through[3]
        self.product = self.cpe_pass_through[4]
        self.version = self.cpe_pass_through[5]
        self.update = self.cpe_pass_through[6]
        self.edition = self.cpe_pass_through[7]
        self.language = self.cpe_pass_through[8]
        self.sw_edition = self.cpe_pass_through[9]
        self.target_sw = self.cpe_pass_through[10]
        self.target_hw = self.cpe_pass_through[11]
        self.other = self.cpe_pass_through[12]

        vuln_cves = self.search(cpe_version=self.cpe_version, part = self.part, vendor= self.vendor, product=self.product, version = self.version)

        return(vuln_cves)
        # print(self.cpe)

    def search(self, **kwargs):
        vuln_cves = []


        funcs = [partial(self.search_file, data_file, **kwargs) for data_file in self.data_files]
        try:
            with Pool(self.proc_num) as p:
                r = list(tqdm(p.imap(self.worker, funcs), 'Processing data files', total=len(funcs)))

            for sub_list in r:
                vuln_cves += sub_list
        except:
            logging.info('failed at tqdm')



        return vuln_cves


    def _init_dirs(self):
        try:
            # print(self.data_dir)
            os.mkdir(self.data_dir)
        except OSError as exec:
            if exc.errno != errno.EEXIST:
                raise
            pass

    # kwargs::  {'vendor': 'unrealircd', 'product': 'unrealircd', 'cpe_version': '2.3', 'json': 'json'}
    # kwargs::  {'cpe_version': '2.3', 'part': 'a', 'vendor': 'openbsd', 'product': 'openssh'}
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Search for CVEs')
    parser.add_argument('--vendor', action='store',
                        help='The vendor the CVE applies to')
    parser.add_argument('--cpe', action='store',
                        help='The CPE string')
    parser.add_argument('--cpe_version',action='store',
                        help='The CPE version of for the CVE')
    parser.add_argument('--part',  action='store',
                        help='The type of item the CVE applies to (a, o, h)')
    parser.add_argument('--product',  action='store',
                        help='The product/library that the CVE applies to')
    parser.add_argument('--version',  action='store',
                        help='The version of software/hardware that the CVE applies to')
    parser.add_argument('--update',  action='store',
                        help='The update number of the vulnerable software/hardware')
    parser.add_argument('--edition',  action='store',
                        help='The update number of the vulnerable software/hardware')
    parser.add_argument('--language',  action='store',
                        help='The language of the vulnerable software/hardware')
    parser.add_argument('--sw_edition',  action='store',
                        help='The software edition of the vulnerable software/hardware')
    parser.add_argument('--target_sw',  action='store',
                        help='The target software of the vulnerable software/hardware')
    parser.add_argument('--target_hw',  action='store',
                        help='The target hardware of the vulnerable software/hardware')
    parser.add_argument('--other',  action='store',
                    help='The other features of the vulnerable software/hardware')
    parser.add_argument('--json',  action='store_true', default=None,
                    help='Switch to json output')

    args = vars(parser.parse_args())

    json_flag = args.pop('json')
    #prune none values
    args = {k: v for k, v in args.items() if v is not None}
    d = {}


    c = cve_searcher()
    # vuln_cves = c.search(vendor='openbsd', product='openssh', cpe_version='2.3', version='4.7p1')
    vuln_cves = c.search(**args)


    if json_flag:
        for cve in vuln_cves:
            logging.debug(cve.data)
    else:
        for cve in vuln_cves:
            logging.debug(f'---{cve.id}---')
            logging.debug(f'{cve.description}')
