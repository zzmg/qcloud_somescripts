# -*- coding: utf-8 -*-

import hmac
import hashlib
import requests
import time
import urlparse
import urllib
import json


class auth(object):

    def __init__(self, sid, skey):
        self._secretid, self._secretkey = str(sid), str(skey)

    def get_sign(self, method, uri, params=None, headers=None):
        '''和cos、cam签名一致，都不对body算签名，这里传了body形参，但没有用到
        '''

        # Step1: 拼接 HttpRequestInfo
        # HttpRequestInfo = Method + "\n"
        #                   + Uri + "\n"
        #                   + FormatedParameters + "\n"
        #                   + FormatedHeaders + "\n"
        if headers == None:
            headers = {}
        if params == None:
            params = {}  # 异常判断

        format_str = '%s\n' % method.lower() + \
                     '%s\n' % (uri) + \
                     '&'.join(['%s=%s' % (k.lower(), urllib.quote_plus(str(params[k]))) for k in sorted(params.keys())]) + '\n' + \
                     '&'.join(['%s=%s' % (key.lower(), urllib.quote_plus(
                         headers[key])) for key in sorted(headers.keys())]) + '\n'                     
        # Step2: 拼接 StringToSign
        # StringToSign = q - sign - algorithm + "\n"
        #              + q - sign - time + "\n"
        #              + sha1(HttpRequestInfo) + "\n"
        start_sign_time = int(time.time())
        sign_time = '%s;%s' % (start_sign_time - 10, start_sign_time + 1000000)
        sha1 = hashlib.sha1()
        sha1.update(format_str)
        str_to_sign = 'sha1\n' + '%s\n' % sign_time + sha1.hexdigest() + '\n'

        # Step3: 生成SignKey
        # SignKey = Hexdigest(HMAC - SHA1(q - key - time, SecretKey))
        hashed = hmac.new(self._secretkey, '%s' % sign_time, hashlib.sha1)
        sign_key = hashed.hexdigest()

        # Step4: 生成 Signature
        # Signature = Hexdigest(HMAC - SHA1(StringToSign, SignKey))
        hasded1 = hmac.new(sign_key, str_to_sign, hashlib.sha1)
        sign = hasded1.hexdigest()

        # Step5: 拼接最后的签名 Authorization
        tmp_header = dict(headers)
        param_list = ';'.join([k.lower() for k in sorted(params.keys())])
        header_list = ';'.join([k.lower() for k in sorted(tmp_header.keys())])
        auth_tuple = (self._secretid, sign_time, sign_time,
                      header_list, param_list,sign)
        print auth_tuple
        return 'q-sign-algorithm=sha1&q-ak=%s&q-sign-time=%s&q-key-time=%s&q-header-list=%s&q-url-param-list=%s&q-signature=%s' % (auth_tuple)


def get_logset_info(auth, host, headers):
    uri = '/logset'
    params = {'logset_id': '157df44f-5746-4ed3-a127-b40d26bcfd6e'}
    call_api('get', host, uri, headers, params)


def get_shipper_info(auth, host, headers):
    uri = '/shipper'
    params = {'shipper_id': '895f3b37-9839-4fea-b542-828e2404db84'}
    call_api('get', host, uri, headers,params)

def get_topic_shipper_info(auth, host, headers):
    uri = '/shippers'
    params = {'topic_id': 'fd477db7-7905-4e5d-9c1d-0e543d81a31a'}
    call_api('get', host, uri, headers, params)

def post_shipper_info(auth, host, headers,service):
    uri = '/shipper'
    params = {
        "topic_id": "fd477db7-7905-4e5d-9c1d-0e543d81a31a",
        "bucket": "log-1258626455",
        "prefix": "test/" + service,
        "shipper_name": service,
        "interval": 300,
        "max_size": 200,
        "partition": "/%Y/%m/%d/",
        "compress": {
            "format": "gzip"
        },
        "content": {
            "format": "json",
        },
        "filter_rules": [{
            "key": "__CONTENT__",
            "regex": '.*?"(' + service + ')".*?',
            "value": service
        }]
    }
    print params
    call_api('post', host, uri, headers,None,params) 

def call_api(method, host, uri, headers, params,data=None):
    sign = auth.get_sign(method, uri, {}, {})
    headers['Authorization'] = sign
    
    endpoint = "http://%s%s" % (host, uri)
    if params: 
            endpoint = endpoint + '?' + urllib.urlencode(params)

    if method == 'get':
        res = requests.request(method, endpoint, headers=headers)
    elif method == 'post':
        res = requests.request(method, endpoint, headers=headers, data=json.dumps(data))
    print endpoint
    print res.status_code, res.text

def search_log(auth, host, headers):
    uri = '/searchlog'
    params = {
        'logset_id': '157df44f-5746-4ed3-a127-b40d26bcfd6e',
        'topic_ids': '95d32bcf-34a1-467b-a34b-d3ffbe5a8abd',
        'start_time': '2019-07-02 00:00:00',
        'end_time': '2019-07-03 00:00:00',
        'query': '',
        'limit': 10,
    }
    call_api('get', host, uri, headers, params)


if __name__ == '__main__':
    secretid = '**'
    secretkey = '**'
    host = 'ap-shanghai.cls.myqcloud.com'
    auth = auth(secretid, secretkey)
    headers = {'host': host}
    #get_shipper_info(auth, host, headers)
    with open("/Users/zhangmengege/Downloads/service",'r') as f:
        line = f.readline()
        while line:
            line = line.strip()
            post_shipper_info(auth,host,headers,line)
            line = f.readline() 
