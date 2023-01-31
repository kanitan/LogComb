# -*- encoding: utf-8 -*-
'''
@File: rule_list.py
@Describe: Define parsing functions here.
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
import collections
import urllib


# functions
# json format
def json_parser(entry):
    try:
        result = json.loads(entry)
        return result
    except:
        logging.error('Not json.')
        return False

# key1="value1",key2="value2",...
def kv_parser(entry):
    log = entry.strip()+','
    kvs = {}
    regex = re.findall(r'([\w_]+?)="(.*?)",',log.replace('\\"',"!@#$%^&").replace('\\r\\n','!!!!!!!!!!'))
    if not regex:
        logging.error('Not match regex.')
        return False
    for kv in regex:
        kvs[kv[0]]=kv[1].replace('!@#$%^&','"').replace('!!!!!!!!!!','\n')
    try:
        kvs['@timestamp']=kvs["date_time"]
    except:
        pass
    return kvs


# nginx access log
def nginx_parser(entry):
    #copy the log_format config from nginx, 注意转义符号
    log_format_conf='$trackingid,$remote_addr,"$remote_user",\[$time_iso_ms\],$request_method,"$uri",$server_protocol,$host,$request_time,"$upstream_response_time","$upstream_addr","$upstream_connect_time","$upstream_header_time",$status,$body_bytes_sent,"$http_user_agent",$http_x_forwarded_for,$http_x_forwarded_proto,zm_cluster_id:$http_x_zm_cluster_id,cluster: "\[cookie: $cookie_zm_cluster header: $cluster_in_header client: $client_cluster_in_header\]","$api_name","$http_referer",$scheme,$request_length,"$upstream_status","$http_x_zm_real_ip","$getrealip"'
    field_list=re.findall("\$(\w+)",log_format_conf)
    r=re.sub("(\$\w+)",'(.*?)',log_format_conf)
    regex=re.split(r,entry)[1:-1]
    if not regex:
        logging.error('Not match regex.')
        return False
    kvs={}
    for i in range(len(field_list)):
        # print(field_list[i],regex[i+1])
        if not field_list[i]=='':
            kvs[field_list[i]]=regex[i]
    return kvs


# CEF log
def F5_CEF_parser(entry):
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


# App-protect default log format
def f5_parser(kv_list):
    if not isinstance(kv_list,dict):
        return False
    if 'violation_details' not in kv_list:
        return kv_list
    try:
        # ES requires the same field data type to be consistent, so convert dict to list. 
        # TODO: response-violations
        kv_list['violation_details'] = xmltodict.parse(
            kv_list['violation_details'])
        try:
            if isinstance(kv_list['violation_details']['BAD_MSG']['request-violations']['violation'],dict):
                kv_list['violation_details']['BAD_MSG']['request-violations']['violation']=[kv_list['violation_details']['BAD_MSG']['request-violations']['violation']]
        except:
            pass
        try:
            for i in range(len(kv_list['violation_details']['BAD_MSG']['request-violations']['violation'])):
                if 'parameter_data' in kv_list['violation_details']['BAD_MSG']['request-violations']['violation'][i] or 'context' in kv_list['violation_details']['BAD_MSG']['request-violations']['violation'][i]:
                    pass
                else:
                    basic_key=['viol_name','viol_index']
                    kv_list['violation_details']['BAD_MSG']['request-violations']['violation'][i]=collections.OrderedDict([('viol_'+k, v) if k not in basic_key else (k, v) for k, v in kv_list['violation_details']['BAD_MSG']['request-violations']['violation'][i].items()])
            # return data
        except:
            logging.error(traceback.print_exc())
            print('change_keyname error')
    except:
        kv_list.pop('violation_details',None)
        # logging.error(traceback.print_exc())
        pass
    base64_fields = ['param_name', 'name',
                     'value', 'buffer', 'uri', 'object','vio_buffer','cookie_name','cookie_value','viol_param_name','cookie_value','header_name','header_value','viol_uri','request_body','viol_http_sub_violation','viol_extension','viol_header']
    for key in base64_fields:
        kv_list = commons.recursion_decode(key, kv_list)
    try:
        kv_list['request_body']=kv_list['request_body'].replace('\r\n','\n')
    except:
        pass
    kv_list['@timestamp'] = kv_list['date_time']
    return kv_list


# Modsec 
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


def zoom_nginx_parser(entry):
    full_request=''
    for k in entry:
        try:
            decode_v=urllib.parse.unquote(entry[k].replace('\\x','%')).replace('\\r\\n','\n')
            entry[k]=decode_v
        except:
            pass
    body='' if entry['request_body']=="-" else entry['request_body']
    full_request=entry['request']+'\n'+entry['request_headers']+'\n\n'+body
    entry['full_request']=full_request
    return entry

def nginx_appsecurity(entry):
    log_format_conf = 'request_time=$time_local client_ip=$remote_addr,server_ip=$server_addr,request_method=$request_method,request_uri=$request_uri,http_cookie=$http_cookie,requestbody=$request_body,status=$status,waf_policy=$app_protect_policy_name, waf_request_id=$app_protect_support_id,waf_action=$app_protect_outcome, waf_action_reason=$app_protect_outcome_reason'
    fields,regex=commons.get_nginx_logformat(log_format_conf)
    values = re.match(regex,entry.strip()).groups()
    if not len(values) == len(fields):
        return False
    kv = {}
    for i in range(len(fields)):
        kv[fields[i]]=values[i]
    return kv

def zoom_monitor_log(entry):
    kv=json.loads(entry)
    param_list=[]
    if 'params' in kv and kv['params']:
        param_keys=sorted(kv['params'].keys())
        for param_key in param_keys:
            param_list.append(param_key+'='+kv['params'][param_key])
    kv['query_string']='&'.join(param_list)
    try:
        kv['query_string']=commons.link_kv(kv['params'],'=','&')
        del kv['params']
    except:
        pass
    try:
        kv['request_header']=commons.link_kv(kv['requestHeaders'],': ','\n')
        del kv['requestHeaders']
    except:
        pass
    try:
        kv['request_cookie']=commons.link_kv(kv['cookies'],'=','; ')
        del kv['cookies']
    except:
        pass
    kv['@timestamp']=kv['requestDate']
    return kv
        