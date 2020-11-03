# -*- encoding: utf-8 -*-
'''
@File: modsec_parser.py
@Describe: 
@Create Time: 2020/07/03 13:54:18
@Author: Lookback
@Version: 1.0
'''
import json
import os
import time

# TODO:
# Seperate normal log and json log.


class modsec_parser:
    # Transform nested dict to flattened dict
    def get_trans(self, entry):
        trans_info = {}
        for items in entry:
            if isinstance(entry[items], dict):
                for key in entry[items]:
                    trans_info[items+'_'+key] = entry[items][key]
                # trans_info = parse_dict(items, entry, trans_info)
            else:
                trans_info[items] = entry[items]
        return trans_info

    # Main function.
    def json_parser(self, entry):
        parsed_log = []
        tran_info = self.get_trans(entry['transaction'])
        if entry['transaction']['messages']:
            temp_trans = tran_info
            temp_trans.pop('messages')
            for items in entry['transaction']['messages']:
                temp_msg = self.get_trans(items)
                temp_msg.update(temp_trans)
                parsed_log.append(temp_msg)
        else:
            parsed_log.append(tran_info)
        return parsed_log

    def log_parser(self, entry):
        try:
            a = json.loads(entry)
            return self.json_parser(a)
        except Exception as e:
            print(e)
            return ''

    # Read from file and parse.
    def file_handler(self, infile, outfile=''):
        if not outfile:
            outfile = os.path.dirname(
                infile)+'/modsec'+str(int(time.time()))+'.log'
        instream = open(infile, 'r')
        outstream = open(outfile, 'w')
        count = 0
        while True:
            if count % 10000 == 0:
                print(count)
            entry = instream.readline()
            if not entry:
                print(outfile)
                print('Finished, total log:', count)
                break
            result = self.log_parser(entry)
            for log in result:
                outstream.write(json.dumps(log))
                outstream.write('\n')
            count = count+1
        return outfile

    def print_result(self, parsed_entry, pretty=True):
        for items in parsed_entry:
            if pretty:
                print(json.dumps(items, indent=4))
            else:
                print(json.dumps(items))


if __name__ == "__main__":
    # Testing
    # put ONLY 1 log line into the example file.
    your_example = '../../testing/example.log'
    parser = modsec_parser()
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), your_example)) as infile:
        example = infile.readline()
        result = parser.log_parser(example)
        parser.print_result(result)
