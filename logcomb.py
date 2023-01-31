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


def get_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        '--prefix', '-pre', help='Decide the prefix of parsed log file name')
    arg_parser.add_argument(
        '--file', '-f', help='Define origin log file to parse.',required=True)
    arg_parser.add_argument(
        '--dir', '-d', help='Define origin log document to parse.')
    arg_parser.add_argument(
        '--parse', '-p', help='Parsing.', action="store_true")   
    arg_parser.add_argument(
        '--send', '-s', help='Send to ES.', action="store_true")
    arg_parser.add_argument(
        "--logtype",help='See rule_list.py to choose specific log type.')
    args = arg_parser.parse_args()
    return args


def main():
    conf_file=os.path.join(os.path.dirname(
            os.path.realpath(__file__)), 'config.conf')
    config = configparser.ConfigParser()
    config.read(conf_file)
    args = get_args()
    # args.prefix
    # args.format
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
