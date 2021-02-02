# -*- encoding: utf-8 -*-
'''
@File: rule_list.py
@Describe: 
@Create Time: 2021/01/11 11:25:59
@Author: Lookback
@Version: 1.0
'''


import commons
import logging
import traceback
import json
import re
import xmltodict


# functions
# json format
def json_parser(entry):
    try:
        result = json.loads(entry)
        return result
    except:
        logging.error('Not json.')
        return False
    return False

# key1="value1",key2="value2",...
def kv_parser(entry):
    log = entry.replace('\\"','````````')
    kvs = {}
    regex = re.findall(r'([\w_]+?)="(.*?)"',log)
    if not regex:
        logging.error('Not match regex.')
        return False
    for kv in regex:
        kvs[kv[0]]=kv[1].replace('````````','\\"')
    return kvs

def nginx_parser(entry):
    regex = re.split(r'request_time=(.*) client_ip=(.*),server_ip=(.*),request_method=(.*),request_uri=(.*),request_header=(.*),upstream_address=(.*),requestbody=(.*),status=(.*),waf_policy=(.*), waf_request_id=(.*),waf_action=(.*), waf_action_reason=(.*)',entry)
    if not regex:
        logging.error('Not match regex.')
        return False      
    field_list = ['request_time','client_ip','server_ip','request_method','request_uri','request_header','upstream_address','requestbody','status','waf_policy','waf_request_id','waf_action','waf_action_reason']
    kvs={}
    for i in range(len(field_list)):
        # print(field_list[i],regex[i+1])
        if not field_list[i]=='':
            kvs[field_list[i]]=regex[i+1]
    return kvs          

def CEF_parser(entry):
    regex=re.split(r'CEF:(\d+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|dvchost=(.*?) dvc=(.*?) cs1=(.*?) cs1Label=(.*?) cs2=(.*?) cs2Label=(.*?) deviceCustomDate1=(.*?) deviceCustomDate1Label=(.*?) externalId=(.*?) act=(.*?) cn1=(.*?) cn1Label=(.*?) src=(.*?) spt=(.*?) dst=(.*?) dpt=(.*?) requestMethod=(.*?) app=(.*?) cs5=(.*?) cs5Label=(.*?) rt=(.*?) deviceExternalId=(.*?) cs4=(.*) cs4Label=(.*) cs6=(.*) cs6Label=(.*) c6a1=(.*) c6a1Label=(.*) c6a2=(.*) c6a2Label=(.*) c6a3=(.*) c6a3Label=(.*) c6a4=(.*) c6a4Label=(.*) msg=(.*) suid=(.*) suser=(.*) cn2=(.*) cn2Label=(.*) cn3=(.*) cn3Label=(.*) microservice=(.*) request=(.*) cs3Label=(.*) cs3=(.*)',entry.replace('\|','````````'))
    if not regex:
        logging.error('Not match regex.')
        return False        
    field_list=['CEFVersion','DeviceVendor','DeviceProduct','DeviceVersion','sig_id','sig_name','DeviceSeverity','','','policy_name','','http_class_name','','collect_date','','support_id','request_status','response_code','','src_ip','src_port','dest_ip','dest_port','requestMethod','app','x_forwarded_for_header_value','','rt','deviceExternalId','attack_type','','geo_location','','','','','','','','','','msg','suid','suser','violation_rating','','device_id','','microservice','uri','','full_request']
    kvs={}
    for i in range(len(field_list)):
        # print(field_list[i],regex[i+1])
        if not field_list[i]=='':
            kvs[field_list[i]]=regex[i+1]
    return kvs        

    
def f5_parser(kv_list):
    if not isinstance(kv_list,dict):
        return False
    if 'violation_details' not in kv_list:
        return False
    try:
        kv_list['violation_details'] = xmltodict.parse(
            kv_list['violation_details'])
        try:
            if isinstance(kv_list['violation_details']['BAD_MSG']['request-violations']['violation'],dict):
                kv_list['violation_details']['BAD_MSG']['request-violations']['violation']=[kv_list['violation_details']['BAD_MSG']['request-violations']['violation']]
        except:
            pass
        try:
            for i in range(len(data['violation_details']['BAD_MSG']['request-violations']['violation'])):
                if 'parameter_data' in data['violation_details']['BAD_MSG']['request-violations']['violation'][i] or 'context' in data['violation_details']['BAD_MSG']['request-violations']['violation'][i]:
                    pass
                else:
                    basic_key=['viol_name','viol_index']
                    data['violation_details']['BAD_MSG']['request-violations']['violation'][i]=collections.OrderedDict([('viol_'+k, v) if k not in basic_key else (k, v) for k, v in data['violation_details']['BAD_MSG']['request-violations']['violation'][i].items()])
            return data
        except:
            logging.error(traceback.print_exc())
            print('change_keyname error')
        if temp:
            kv_list=temp
        else:
            pass
    except:
        logging.error(traceback.print_exc())
        pass
    base64_fields = ['param_name', 'name',
                     'value', 'buffer', 'uri', 'object','vio_buffer']
    for key in base64_fields:
        kv_list = commons.recursion_decode(key, kv_list)
    return kv_list

def modsec_parser(kv_list):
    if not isinstance(kv_list,dict):
        return False
    if not 'transaction' in kv_list:
        return False
    parsed_log = []
    tran_info = commons.get_trans(kv_list['transaction'])
    if kv_list['transaction']['messages']:
        temp_trans = tran_info
        temp_trans.pop('messages')
        for items in kv_list['transaction']['messages']:
            temp_msg = commons.get_trans(items)
            temp_msg.update(temp_trans)
            parsed_log.append(temp_msg)
    else:
        parsed_log.append(tran_info)
    return parsed_log
