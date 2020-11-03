# -*- encoding: utf-8 -*-
'''
@File: f5_parser.py
@Describe: 
@Create Time: 2020/09/16 15:26:24
@Author: Lookback
@Version: 1.0
'''
import re
import xmltodict
import time
import os
import json
import base64
import traceback
import logging
import operator
from functools import reduce
from pprint import pprint
import collections


# base64 decode
def base64_decode(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    return message


class f5_parser:
    def log_parser(self, entry):
        result = {}
        regex = re.findall(r'([\w_]+)?="(.*?)"',
                           entry.replace('""', '````````'))
        # print(regex)                   
        for items in regex:
            result[items[0]] = items[1].replace('````````', '"')
        # xml parse
        try:
            result['violation_details'] = xmltodict.parse(
                result['violation_details'])
            try:
                if isinstance(result['violation_details']['BAD_MSG']['request-violations']['violation'],dict):
                    result['violation_details']['BAD_MSG']['request-violations']['violation']=[result['violation_details']['BAD_MSG']['request-violations']['violation']]
            except:
                pass
            temp=self.change_keyname(result)
            if temp:
                result=temp
            else:
                pass
        except:
            logging.error(traceback.print_exc())
            return False
        base64_fields = ['param_name', 'name',
                         'value', 'buffer', 'uri', 'object']
        for key in base64_fields:
            result = self.base64(key, result)
        return result

    def get_value(self, data, key):
        if isinstance(data, list):
            return reduce(operator.add, data[key])
        else:
            return data[key]

    def change_keyname(self,data):    # if the viol_name is not VIOL_ATTACK_SIGNATURE, the data type of keys will change, which doesn't match ES's mapping
        try:
            for i in range(len(data['violation_details']['BAD_MSG']['request-violations']['violation'])):
                if 'parameter_data' in data['violation_details']['BAD_MSG']['request-violations']['violation'][i] or 'context' in data['violation_details']['BAD_MSG']['request-violations']['violation'][i]:
                    pass
                else:
                    basic_key=['viol_name','viol_index']
                    data['violation_details']['BAD_MSG']['request-violations']['violation'][i]=collections.OrderedDict([('vio_'+k, v) if k not in basic_key else (k, v) for k, v in data['violation_details']['BAD_MSG']['request-violations']['violation'][i].items()])
            return data
        except:
            logging.error(traceback.print_exc())
            print('change_keyname error')
            return False



    def base64(self, key, violation):
        if isinstance(violation, dict):
            for items in violation:
                if items == key:
                    try:
                        violation[items] = base64_decode(violation[items])
                    except:
                        pass
                else:
                    violation[items] = self.base64(key, violation[items])
        elif isinstance(violation, list):
            for items in violation:
                items_list=[]
                for list_i in violation:
                    items_list.append(self.base64(key, list_i))
                violation=items_list
            else:
                pass
        else:
            pass
        return violation

    # Handle f5 logs. Return parsed log name.
    def file_handler(self, infile, outfile=''):
        if not outfile:
            outfile = os.path.dirname(
                infile)+'/applog'+str(int(time.time()))+'.log'
        instream = open(infile, 'r', encoding='utf-8')
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
            result = json.dumps(self.log_parser(line))
            if not result == 'false':
                outstream.write(result)
                outstream.write('\n')
            else:
                logging.warning('Not particular log format. Position: %s \n', count)
            count = count+1
        return outfile

    def print_result(self, parsed_entry, pretty=True):
        if pretty:
            print(json.dumps(parsed_entry, indent=4))
        else:
            print(json.dumps(parsed_entry))


if __name__ == "__main__":
    parser = f5_parser()
    # Test Here.
    # put ONLY 1 log line into the example file.
    your_example = '../../testing/example.log'
    log_path=os.path.join(os.path.dirname(os.path.realpath(__file__)), your_example)
    print(log_path)
    with open(log_path) as infile:
        example = infile.readline()
        result = parser.log_parser(example)
        parser.print_result(result)

    # Test file
    # log_path='/Users/PennyLang/Documents/WAF/app-protect/log/app_log.log-20201028'
    # parser.file_handler(log_path)

    
