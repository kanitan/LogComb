# -*- encoding: utf-8 -*-
'''
@File: main.py
@Describe: 
@Create Time: 2020/09/17 16:56:32
@Author: Lookback
@Version: 1.0
'''
from es_sender import es_sender
import parse as p
import argparse
import configparser
import os
import commons


def get_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        '--prefix', '-pre', help='Decide the prefix of parsed log file name')
    arg_parser.add_argument(
        '--file', '-f', help='Define origin log file to parse.')
    arg_parser.add_argument(
        '--dir', '-d', help='Define origin log document to parse.')
    arg_parser.add_argument(
        '--parse', '-p', help='Parsing.', action="store_true")   
    arg_parser.add_argument(
        '--send', '-s', help='Send to ES.', action="store_true")
    arg_parser.add_argument(
        "--logtype",help='See rule_list.py to choose specific log type.')
    arg_parser.add_argument("--test",'-t',help="Run testing.", action="store_true")
    args = arg_parser.parse_args()
    return args


def main():
    script_path=os.path.dirname(
            os.path.realpath(__file__))
    conf_file=os.path.join(script_path, 'config.conf')
    config = configparser.ConfigParser()
    config.read(conf_file)
    args = get_args()
    # args.prefix
    # args.format
    if args.test:
        test_path=os.path.join(script_path,'testing/example.log')
        with open(test_path) as infile:
            example = infile.readline()
            test_p = p.log_parser('splunk')
            result = test_p.entry_parser(example)
            print(example)
            # print log
            commons.print_result(result)
            print('\n\n====response_body==========================')

            print(result['response_body'])
            print('====response_body End==========================\n')
            print('====full_request==========================')
            print(result['full_request'])
            print('====full_request End==========================')
        return
    if not args.file:
        print('Please define file path with argument --file/f. Use --help to see details.')
        return 
    log_type=''
    if config['parser']['log_type']:
        log_type=config['parser']['log_type']
    elif args.logtype:
        log_type=args.logtype
    else:
        log_type=p.get_file_log_type(args.file)
        
    
    # args.parse
    if args.parse:
        new_parser=p.log_parser(log_type)
        parsed_file = new_parser.file_parser(args.file)
    else:
        parsed_file=args.file
    # args.send
    if args.send:
        sender = es_sender(parsed_file,conf_file)
        sender.send_file()


if __name__ == "__main__":
    main()
