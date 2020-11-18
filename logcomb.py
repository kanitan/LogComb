# -*- encoding: utf-8 -*-
'''
@File: main.py
@Describe: 
@Create Time: 2020/09/17 16:56:32
@Author: Lookback
@Version: 1.0
'''
from lib.sender.es_sender import es_sender
from lib.parser.f5_parser import f5_parser
from lib.parser.f5cef_parser import f5cef_parser
from lib.parser.modsec_parser import modsec_parser
import argparse
import configparser
import logging
import os


device_list = {'App-protect': 'attack_type="', 'ModesecurityJson': '{"transaction":{"',
               'ModesecurityNormal': '-A--', 'Naxsi': 'NAXSI_FMT','App-protect-CEF':'CEF:'}


def get_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        '--type', '-t', help='Identify log type. By default, the script will automaticly check log type. Supporting types: \nModesecurity, ModesecurityJson, Naxsi, App-protect.')
    arg_parser.add_argument(
        '--file', '-f', help='Define origin log file to parse.',required=True)
    arg_parser.add_argument(
        '--dir', '-d', help='Define origin log document to parse.')
    arg_parser.add_argument(
        '--parse', '-p', help='Parsing.', action="store_true")   
    arg_parser.add_argument(
        '--send', '-s', help='Send to ES.', action="store_true")
    args = arg_parser.parse_args()
    return args

# Identify which log
def get_devicetype(file):
    try:
        with open(file) as f:
            firstline = f.readline()
            for items in device_list:
                if firstline.startswith(device_list[items]):
                    return items
            return False
    except Exception as e:
        print(e)
        return False

# Parse log
def parse_file(filename, device_type):
    if device_type == 'App-protect':
        parser = f5_parser()
    elif device_type == 'App-protect-CEF':
        parser=f5cef_parser()
    elif device_type.startswith('Modesecurity'):
        parser = modsec_parser()
    else:
        logging.error('Unrecognized log type. Quit.')
        return False
    return parser.file_handler(filename)


def main():
    conf_file=os.path.join(os.path.dirname(
            os.path.realpath(__file__)), 'config.conf')
    config = configparser.ConfigParser()
    config.read(conf_file)
    args = get_args()
    # args.type
    if config['parser']['device_type'] in device_list:
        device_type=config['parser']['device_type']
    elif args.type in device_list:
        device_type = args.type
    else:
        device_type = get_devicetype(args.file)
    # args.parse
    if args.parse:
        parsed_file = parse_file(args.file, device_type)
    else:
        parsed_file=args.file
    # args.send
    if args.send:
        sender = es_sender(parsed_file,conf_file)
        sender.send_file()


if __name__ == "__main__":
    main()
