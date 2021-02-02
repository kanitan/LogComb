# -*- encoding: utf-8 -*-
'''
@File: parse.py
@Describe: 
@Create Time: 2020/11/30 17:09:45
@Author: Lookback
@Version: 1.0
'''



import re
import random
import logging
import traceback
import time
import os
import json
import commons
import mapping
import xmltodict


class log_parser:
# Give me log, give you result.
    def __init__(self,entry):
        # load rules
        ## load regex expressions
        self.entry = entry
        self.log_type = self.get_log_type(entry)
        self.rule_count = len(mapping.mapping[self.log_type])-1
        if self.rule_count>0:
            self.functions = mapping.mapping[self.log_type][1:]
        else:
            self.functions == None


    def get_log_type(self,entry):
        for rule in mapping.mapping:
            if self.entry.startswith(mapping.mapping[rule][0]):
                return rule
        logging.error('No suitable parsing rule.')
        return ''

    def parse_log(self):
        if not self.functions:
            logging.warn('Rule not defined. Quit')
            return False
        result = self.entry
        for function in self.functions:
            try:
                result = function(result)
            except:
                logging.error(traceback.print_exc())
                return False
        return result


# File handler
class file_parser:
    def __init__(self,infile, prefix='',outfile=''):
        self.infile = infile
        with open(infile) as i:
            line = i.readline()
            p = log_parser(line)
            self.log_type=p.log_type
        if prefix:
            self.prefix = prefix
        else:
            self.prefix = self.log_type
        if not outfile:
            self.outfile = os.path.join(os.path.dirname(infile),self.prefix+str(int(time.time()))+'.log')
        else:
            self.outfile=outfile

    def file_handler(self):
        instream = open(self.infile, 'r', encoding='utf-8')
        outstream = open(self.outfile, 'w')       
        count = 0
        while True:
            if count % 10000 == 0:
                print(count)
            line = instream.readline()
            if not line:
                print(self.outfile)
                print('Finished, total log:', count)
                break
            p = log_parser(line)
            if not p.log_type:
                logging.warning('Not particular log format. Position: %s \n', count)
                continue
            else:
                self.log_type=p.log_type
                result = p.parse_log()
                if not result:
                    logging.error('Parsing failed. Position: %s \n',count)
                    continue
            if isinstance(result,dict):
                outstream.write(json.dumps(result))
                outstream.write('\n')
            if isinstance(result,list):
                for item in result:
                    outstream.write(json.dumps(item))
                    outstream.write('\n')                   
            count = count+1


if __name__ == "__main__":
    your_example = 'testing/example.log'
    log_path=os.path.join(os.path.dirname(os.path.realpath(__file__)), your_example)
    print(log_path)
    # f=file_parser(log_path)
    # f.file_handler()
    with open(log_path) as infile:
        example = infile.readline()
        p = log_parser(example)
        result = p.parse_log()
        commons.print_result(result)
        
