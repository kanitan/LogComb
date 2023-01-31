# -*- encoding: utf-8 -*-
'''
@File: commons.py
@Describe: 
@Create Time: 2020/12/31 17:19:40
@Author: Lookback
@Version: 1.0
'''



import json
import base64
import re


# Print single parsed log.
def print_result(parsed_entry, pretty=True):
    if pretty:
        print(json.dumps(parsed_entry, indent=4))
        try:
            method=parsed_entry['method']
            uri=parsed_entry['uri']
            query_string='' if parsed_entry['query_string']=="N/A" else '?'+parsed_entry['query_string']
            header=parsed_entry['request_header']
            body='' if parsed_entry['request_body']=="N/A" else parsed_entry['request_body']
            print(method,uri+query_string, 'HTTP/1.1',sep=' ')
            print(header)
            print(body)
            print('\n\n')
            useful_fields=['policy_name','attack_type','severity','violations','sub_violations','violation_rating','sig_ids','sig_names','sig_set_names','sig_cves','threat_campaign_names','bot_anomalies','bot_category','bot_signature_name','enforced_bot_anomalies']
            for u in useful_fields:
                print(u,':',parsed_entry[u])
            print(json.dumps(parsed_entry['violation_details'],indent=4))
        except:
            pass
    else:
        print(json.dumps(parsed_entry))


def base64_decode(base64_message):
    base64_bytes = base64_message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('utf-8')
    return message

def recursion_decode(key, violation):
     if isinstance(violation, dict):
         for items in violation:
             if items == key:
                 try:
                    violation[items]=base64_decode(violation[items])
                 except:
                    #  print(violation[items],'base64 failed')
                     pass
             else:
                 violation[items] = recursion_decode(key, violation[items])
     elif isinstance(violation, list):
         for items in violation:
             items_list=[]
             for list_i in violation:
                 items_list.append(recursion_decode(key, list_i))
             violation=items_list
         else:
             pass
     else:
         pass
     return violation



# Transform nested dict to flattened dict
def get_trans(entry):
    flat_dict = {}
    for items in entry:
        if isinstance(entry[items], dict):
            for key in entry[items]:
                flat_dict[items+'_'+key] = entry[items][key]
        else:
            flat_dict[items] = entry[items]
    return flat_dict


# allow users to put log_format configuration and generate regex string automaticly.
def get_nginx_logformat(log_config):
    fields=re.findall(r'\$(\w+)\b',log_config.replace('[','\[').replace('([)','\('))
    regex=re.sub(r'\$(\w+)\b','(.*)',log_config)
    if not fields or not regex:
        return False
    return fields,regex


def link_kv(dict_value,equl_symbol,split_symbol):
    result_list=[]
    result_keys=sorted(dict_value.keys())
    for result_key in result_keys:
        result_list.append(result_key+equl_symbol+dict_value[result_key])
    return split_symbol.join(result_list)