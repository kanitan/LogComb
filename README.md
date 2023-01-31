# LogComb --A Security Log Toolkit

A log toolkit for security devices. The main idea of this tool is to make analyzers to concern on analysis rather than data preprocessing. Start to save your time.

Avalible Devices Now: [Modsecurity](https://github.com/SpiderLabs/ModSecurity),[App-protect](https://docs.nginx.com/nginx-app-protect/admin-guide/).

- [zh-cn 中文](zh-cn/README.md)

This logpaser is for  **Security Device Datas**. It's a great tool to parse logs, send to ELK. Start your analysis more quickly!

Prepare your [ELK](https://elk-docker.readthedocs.io/) if you want to **visualize** datas.

**TODO List**

- [x] Parsing logs
- [x] Send parsed log to es server
- [x] Support custom parsing rules.
- [x] Support regex, custom functions.
- [x] Built-in parsing rules
  - [x] F5 waf(app-protect)
  - [x] Modsecurity json format
  - [ ] Modsecurity normal format
  - [x] F5 CEF format(app-protect)
  - [x] Splunk alert
  - [x] Nginx comma seperated 
  - [ ] Naxsi
- [x] Auto recognize log type.

- [ ] Parse log to the STANDERD format. **Notice**: This mode requires user to fill a table to tell the tool the meaning of field. Feel easy to fill the table, and don't worry about losing datas.



## Usage

### Quick Start

Config your Elasticsearch address in ``config.conf`` and run

```bash
python ./logcomb.py -f /var/log/modsec_audit.log -ps
```

Logcomb will parse the log and send result to ES.

### Parameters

```shell
usage: logcomb.py [-h] [--prefix PREFIX] --file FILE [--dir DIR] [--parse]
                  [--send]

optional arguments:
  -h, --help            show this help message and exit
  --prefix PREFIX, -pre PREFIX
                        Decide the prefix of parsed log file name.
  --file FILE, -f FILE  Define origin log file to parse.
  --dir DIR, -d DIR     Define origin log document to parse.
  --parse, -p           Parsing.
  --send, -s            Send to ES.
```





## Testing

### Parsing Testing

Put one line log to test/example.log and run

```
python parse.py
```

And you will see the parsed log in terminal.

