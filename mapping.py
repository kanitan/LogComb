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
# key name should be lowercase
mapping = {
    'app-protect': ['attack_type="',r.kv_parser,r.f5_parser], 
    'modesecurity-json': ['{"transaction":{"',r.json_parser,r.modsec_parser],
    'modesecurity-normal': ['-A--'], 
    'naxsi': ['NAXSI_FMT'],
    'app-protect-cef':['CEF:',r.F5_CEF_parser],
    'splunk':['unit_hostname',r.kv_parser,r.f5_parser],
    # 'nginx_appsecurity':['request_time',r.nginx_appsecurity],
    'nginxaccesslog':['WEB_',r.nginx_parser],
    'zoom-nginxaccesslog':['request_time',r.kv_parser,r.zoom_nginx_parser],
    'zoom-monitorlog':['{"requestDate": ',r.zoom_monitor_log]
    }

