# -*- encoding: utf-8 -*-
'''
@File: parse.py
@Describe: Main function.
@Create Time: 2020/11/30 17:09:45
@Author: Lookback
@Version: 2.1
'''



import logging
import traceback
import time
import os
import json
import commons
import mapping
import json

def get_log_type(entry):
    for rule in mapping.mapping:
        if entry.startswith(mapping.mapping[rule][0]):
            return rule
    logging.error('No suitable parsing rule.')
    return ''

def get_file_log_type(infile):
        with open(infile,errors='ignore') as i:
            line = i.readline()
        return get_log_type(line)


def get_function_name(log_type):
    #load rules
    if log_type in mapping.mapping:
        return  mapping.mapping[log_type][1:]
    else:
        return False



class log_parser:
# Give me log, give you result.
    def __init__(self,log_type=''):
        # load rules
        ## load regex expressions
        if log_type:
            self.log_type = log_type
        else:
            logging.error('Can\'t find log type. Please define log type. Or you can use get_log_type(entry) or get_file_log_type(infile) to detect the log type automaticly.')
            return False

    def entry_parser(self,entry):
        functions=get_function_name(self.log_type)
        if not functions:
            logging.warn('Rule not defined. Quit')
            return False
        result = entry.strip().strip('\x00')
        for function in functions:
            try:
                result = function(result)
            except:
                logging.error(traceback.print_exc())
                return False
        return result

    
    def file_parser(self,infile,prefix='',outfile=''):
        if not prefix:
            prefix=self.log_type
        if not outfile:
            outfile = os.path.join(os.path.dirname(infile),prefix+str(int(time.time()))+'.log')
        instream = open(infile, 'r', encoding='utf-8',errors='replace')
        outstream = open(outfile, 'w')
        count = 0
        while True:
            if count % 10000 == 0:
                print(count)
            line = instream.readline()
            if not line:
                print(outfile)
                print('Finished, total log:', count)
                break
            result = self.entry_parser(line)
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
        return outfile


if __name__ == "__main__":
    your_example = '/Users/PennyLang/Desktop/SourceCode/LogComb/testing/example.log'
    # your_example = '/Users/PennyLang/Downloads/example.log'
    log_path=os.path.join(os.path.dirname(os.path.realpath(__file__)), your_example)
    print(log_path)
    # f=file_parser(log_path)
    # f.file_handler()
    with open(log_path) as infile:
        example = infile.readline()
        p = log_parser('splunk')
        result = p.entry_parser(example)
        print(example)
        # print log
        commons.print_result(result)
        print('\n\n====response_body==========================')

        print(result['response_body'])
        print('====response_body End==========================\n')
        print('====full_request==========================')
        print(result['full_request'])
        print('====full_request End==========================')