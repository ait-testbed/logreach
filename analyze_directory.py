#!/usr/bin/env python3

from logmate.logfile import Logfile,config_factory
from logmate.schemas.logline import Logline
import os
import json
import sys
import argparse
import re
import logging
from rich import print

class IgnoreList:
    def __init__(self, ignorelist_file: str):
        self.ignorelist_file = ignorelist_file
        self.patterns = []
        self.compile_regex()
        
    def compile_regex(self):
        with open(self.ignorelist_file, 'r') as list_file:
            for line in list_file:
                self.patterns.append(re.compile(line.rstrip('\n')))

    def is_ignored(self, filepath):
        for pattern in self.patterns:
            if re.search(pattern, filepath):
                return True
        return False


class TypesConf:
    def __init__(self, types_file="logtypes.json"):
        self.file = types_file
        self.data = {}
        self._read_file()

    def _read_file(self):
        with open(self.file, 'r') as types_file:
            for line in types_file:
                item = json.loads(line)
                self.data[item["logfile_path"]] = item

    def check(self, path):
        if path in self.data.keys():
            return True
        return False
        

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def is_ignored_ext(path, ignored_ext):
    blocked_exts = ignored_ext.split(',')
    file,extension = os.path.splitext(path)
    if extension in blocked_exts:
        return True
    return False

def check_syslog(path):
    config = config_factory(path, "syslog")
    try:
        first_line = None
        with Logfile(config, logger=logging.getLogger()) as lf:
            for line in lf:
                first_line = line
                break

        if first_line is None:
            eprint(f"{path} is empty")
            return
        if first_line.timestamp is None:
            eprint(f"{path} needs to be fixed!")
            eprint(first_line)
            exit(1)
        print(first_line)
    except UnicodeDecodeError as e:
        eprint(f"Unsupported filetype: {path}")
        exit(1)



def main():
    parser = argparse.ArgumentParser(
                    prog='analyze_logfiles',
                    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                    description='detects non-syslog logfiles in a directory')
    parser.add_argument('--path', help='directory with logfiles', required=True)
    parser.add_argument('--ignored-extension', help='comma seperated list of ignored file-extensions', default=".gz,.xz,.conf,.journal,.journal~")
    parser.add_argument('--ignorelist-file', help="a file with a list of ignored files. (regex supported)", required=False)
    args = parser.parse_args()
    ilist = None

    try:
        typesconf = TypesConf()
    except FileNotFoundError:
        typesconf = None

    if args.ignorelist_file:
        ilist = IgnoreList(args.ignorelist_file)
    
    for (root,dirs,files) in os.walk(args.path, followlinks=True):
        for file in files:
            full_path = os.path.join(root, file)
            if is_ignored_ext(full_path, args.ignored_extension):
                continue
            if ilist:
                if ilist.is_ignored(full_path):
                    continue
            if typesconf:
                if typesconf.check(full_path):
                    continue
            check_syslog(full_path)
            print(full_path)

if __name__ == "__main__":
    main()
