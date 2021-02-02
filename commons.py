# -*- encoding: utf-8 -*-
'''
@File: commons.py
@Describe: 
@Create Time: 2020/12/31 17:19:40
@Author: Lookback
@Version: 1.0
'''


import time
import os
import json
import logging
import base64
import parser


# Print single parsed log.
def print_result(parsed_entry, pretty=True):
    if pretty:
        print(json.dumps(parsed_entry, indent=4))
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
                     violation[items] = Commons.base64_decode(violation[items])
                 except:
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

