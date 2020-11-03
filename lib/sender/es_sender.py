# -*- encoding: utf-8 -*-
'''
@File: es_sender.py
@Describe: 
@Create Time: 2020/09/16 17:18:15
@Author: Lookback
@Version: 1.0
'''
# add new index: curl -XPUT 'http://localhost:9200/nxapi/'


# TODO:
# -[] Create index automaticly.


from elasticsearch import Elasticsearch, helpers
from datetime import datetime
from time import sleep
import json
import os
import configparser


class es_sender:
    def __init__(self, log_file, conf_file):
        config = configparser.ConfigParser()
        config.read(conf_file)
        self.client = Elasticsearch(config['es_server']['server_name'])
        self.log_file = log_file
        self.req_capacity = int(config['es_server']['req_capacity'])
        if config['es_server']['index']:
            self.index = config['es_server']['index']
        else:
            self.index=os.path.splitext(os.path.split(log_file)[1])[0]
        print(self.index)

    def send(self, doc_list):
        resp = helpers.bulk(
            self.client,
            doc_list,
            index=self.index
        )
        # print('Sending to ES, index',self.index)
        print("helpers.bulk() RESPONSE:", resp)

    def log_sender(self, instream):
        count = 0
        doc_list = []
        while True:
            line = instream.readline()
            if not line:
                self.send(doc_list)
                break
            count = count+1
            doc = json.loads(line)
            doc["@timestamp"] = datetime.now()
            # doc['@timestamp'] = doc['time_stamp']
            doc_list.append(doc)
            if count % self.req_capacity == 0:
                self.send(doc_list)
                doc_list = []
                sleep(1)

    def send_file(self):
        with open(self.log_file, 'r') as instream:
            self.log_sender(instream)


if __name__ == "__main__":
    # Testing
    log_file='/Users/PennyLang/Desktop/Personal Files/toES/Modsec_LogParser/testing/example.log'
    conf_file=os.path.join(os.path.dirname(
            os.path.realpath(__file__)), '../../config.conf')
    sender = es_sender(log_file,conf_file)
    # sender.send_file()
