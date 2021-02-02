# -*- encoding: utf-8 -*-
'''
@File: mapping.py
@Describe: 
@Create Time: 2021/01/11 11:17:24
@Author: Lookback
@Version: 1.0
'''



import rule_list as r

# rule_name:[signature,regex,function1,function2,function3...]

mapping = {
    'App-protect': ['attack_type="',r.kv_parser,r.f5_parser], 
    'ModesecurityJson': ['{"transaction":{"',r.json_parser,r.modsec_parser],
    'ModesecurityNormal': ['-A--'], 
    'Naxsi': ['NAXSI_FMT'],
    'App-protect-CEF':['CEF:',r.CEF_parser],
    'splunk':['unit_hostname',r.kv_parser],
    'nginx':['request_time',r.nginx_parser]
    }

