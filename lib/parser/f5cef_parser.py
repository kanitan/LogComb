# -*- encoding: utf-8 -*-
'''
@File: cef_parser.py
@Describe: 
@Create Time: 2020/11/04 16:53:41
@Author: Lookback
@Version: 1.0
'''

import re
import json
import os
import time
import logging


class f5cef_parser:
    def log_parser(self,entry):
        regex=re.split(r'CEF:(\d+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|dvchost=(.*?) dvc=(.*?) cs1=(.*?) cs1Label=(.*?) cs2=(.*?) cs2Label=(.*?) deviceCustomDate1=(.*?) deviceCustomDate1Label=(.*?) externalId=(.*?) act=(.*?) cn1=(.*?) cn1Label=(.*?) src=(.*?) spt=(.*?) dst=(.*?) dpt=(.*?) requestMethod=(.*?) app=(.*?) cs5=(.*?) cs5Label=(.*?) rt=(.*?) deviceExternalId=(.*?) cs4=(.*) cs4Label=(.*) cs6=(.*) cs6Label=(.*) c6a1=(.*) c6a1Label=(.*) c6a2=(.*) c6a2Label=(.*) c6a3=(.*) c6a3Label=(.*) c6a4=(.*) c6a4Label=(.*) msg=(.*) suid=(.*) suser=(.*) cn2=(.*) cn2Label=(.*) cn3=(.*) cn3Label=(.*) microservice=(.*) request=(.*) cs3Label=(.*) cs3=(.*)',entry.replace('\|','````````'))
        
        field_list=['CEFVersion','DeviceVendor','DeviceProduct','DeviceVersion','sig_id','sig_name','DeviceSeverity','','','policy_name','','http_class_name','','collect_date','','support_id','request_status','response_code','','src_ip','src_port','dest_ip','dest_port','requestMethod','app','x_forwarded_for_header_value','','rt','deviceExternalId','attack_type','','geo_location','','','','','','','','','','msg','suid','suser','violation_rating','','device_id','','microservice','uri','','full_request']
        result={}
        for i in range(len(field_list)):
            # print(field_list[i],regex[i+1])
            if not field_list[i]=='':
                result[field_list[i]]=regex[i+1]
        return result


    def file_handler(self, infile, outfile=''):
        if not outfile:
            outfile = os.path.dirname(
                infile)+'/f5cef'+str(int(time.time()))+'.log'
        instream = open(infile, 'r', encoding='utf-8')
        outstream = open(outfile, 'w')
        count = 0
        while True:
            if count % 10000 == 0:
                print(count)
            line = instream.readline()
            if not line:
                print(outfile)
                print('Finished, total log:', count)
                break
            result = json.dumps(self.log_parser(line))
            if not result == 'false':
                outstream.write(result)
                outstream.write('\n')
            else:
                logging.warning('Not particular log format. Position: %s \n', count)
            count = count+1
        return outfile
    
    def print_result(self, parsed_entry, pretty=True):
        if pretty:
            print(json.dumps(parsed_entry, indent=4))
        else:
            print(json.dumps(parsed_entry))
        




if __name__ == "__main__":
    parser=f5cef_parser()
    # entry='CEF:0|F5|ASM|15.1.0|200010085|/tmp dir access|5|dvchost=\=\=\==\ dvc= cs1=signature_exclude_1 cs1Label=policy_name cs2=signature_exclude_1 cs2Label=http_class_name deviceCustomDate1=Nov 03 2020 08:49:49 deviceCustomDate1Label=policy_apply_date externalId=15649843469809800528 act=blocked cn1=0 cn1Label=response_code src=38.99.100.2 spt=3205 dst=0.0.0.0 dpt=443 requestMethod=GET app=HTTPS cs5=N/A cs5Label=x_forwarded_for_header_value rt=Nov 03 2020 09:38:20 deviceExternalId=0 cs4=Predictable Resource Location cs4Label=attack_type cs6=N/A cs6Label=geo_location c6a1= c6a1Label=device_address c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address c6a4= c6a4Label=ip_address_intelligence msg=N/A suid=0 suser=N/A cn2=4 cn2Label=violation_rating cn3=0 cn3Label=device_id microservice=N/A request=/.svn/tmp/ cs3Label=full_request cs3=GET /.svn/tmp/ HTTP/1.1\\r\\nHost: devb.zoomdev.us\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36\\r\\nAccept-Encoding: gzip, deflate\\r\\nAccept: */*\\r\\nConnection: keep-alive\\r\\n\\r\\n'
    # parsed_entry= parser.log_parser(entry)
    # parser.print_result(parsed_entry)
    parser.file_handler('/Users/PennyLang/Documents/WAF/app-protect/log/app_protect_cef.log')
