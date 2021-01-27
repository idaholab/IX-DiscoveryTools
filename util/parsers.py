from pprint import pprint
import json

class MainParser:
    def __init__(self):
        pass

    def parse(self, text):
        lines = text.split('\n')
        (processed, data) = self.stack(self.count_prefix(lines[0]), lines[1:])

    
    #def to_stix(self, processed_text):

    @staticmethod
    def process_key(text):
        text = text.lstrip().rstrip()
        prefix = '*-'
        if text.startswith(prefix):
            text = text[len(prefix):]
        return  text
    
    def stack(self, main_count, lines):
        l = {}
        next_count = self.count_prefix(lines[0])
        skipper = 0
        processed = 0
        for index, line in enumerate(lines):
            processed += 1
            if skipper > 0:
                skipper -= 1
                continue
            elif self.count_prefix(line) < next_count and self.count_prefix(line) > main_count:
                (to_skip, l[self.process_key(line)]) = self.stack(self.count_prefix(line), lines[index+1:])
                skipper += to_skip
            elif self.count_prefix(line) == next_count:
                sections = line.split(':', 1)
                l[self.process_key(sections[0])] = sections[1].lstrip()
            elif line == '':
                continue
            else:
                processed -= 1
                break
        return (processed, l)

    def count_prefix(self, line):
        return len(line) - len(line.lstrip(' '))