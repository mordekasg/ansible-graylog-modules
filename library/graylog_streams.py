#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Whitney Champion <whitney.ellis.champion@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
from re import I
__metaclass__ = type



# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url 
from ansible.module_utils._text import to_text
import sys, os, re, json, base64

from ansible.module_utils.graylog_helpers import *

def get_stream_info_by_id(module, base_url, headers, stream_id):
    url = "{base_url}/api/streams/{id}".format(base_url=base_url, id=stream_id)
    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        data = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')
        data = {}

    # raise Exception(data)
    return data


def create_or_update(module, base_url, headers):

    index_set_id = default_index_set(module, base_url, headers)

    stream_id = query_streams(module, base_url, headers, module.params['title'])

    # raise Exception(stream_id)
    if stream_id == "":
      httpMethod = "POST"
      url = base_url + "/api/streams"
      data_pre = {}
    else:
      httpMethod = "PUT"
      url = base_url + "/api/streams/" + stream_id
      data_pre = get_stream_info_by_id(module, base_url, headers, stream_id)


    payload = {}

    for key in ['title', 'description', 'remove_matches_from_default_stream', 'matching_type', 'rules']:
      if module.params[key] is not None and module.params[key] != "":
        payload[key] = module.params[key]

    payload['index_set_id'] = index_set_id

    # raise Exception(payload)
    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method=httpMethod, data=module.jsonify(payload))

    if info['status'] != 201 and info['status'] != 200 and info['status'] != 204:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    data_post = get_stream_info_by_id(module, base_url, headers, stream_id)

    return info['status'], info['msg'], content, url, not compare_dict(data_pre, data_post)


def delete(module, base_url, headers):
    stream_id = query_streams(module, base_url, headers, module.params['title'])

    if stream_id == "":
        return 0, "Already non-existent", "Nothing to do", base_url, False

    url = base_url + "/api/streams/" + stream_id

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='DELETE')

    if info['status'] != 204:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url, True


def start(module, base_url, headers):
    stream_id = query_streams(module, base_url, headers, module.params['title'])

    url = "{base_url}/api/streams/{id}/resume".format(base_url=base_url, id=stream_id)

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='POST')

    if info['status'] != 201 and info['status'] != 200 and info['status'] != 204:
        raise Exception(info)
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def query_streams(module, base_url, headers, stream_name):

    url = base_url + "/api/streams"

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        streams = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')

    stream_id = ""
    if streams is not None:

        i = 0
        while i < len(streams['streams']):
            stream = streams['streams'][i]
            if stream_name == stream['title']:
                stream_id = stream['id']
                break
            i += 1

    return stream_id


def default_index_set(module, base_url, headers):

    url = base_url + "/api/system/indices/index_sets?skip=0&limit=0&stats=false"

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        indices = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')

    default_index_set_id = ""
    if indices is not None:
        default_index_set_id = indices['index_sets'][0]['id']

    return default_index_set_id

def main():
    module = AnsibleModule(
        argument_spec=dict(
            endpoint=dict(type='str'),
            graylog_user=dict(type='str'),
            graylog_password=dict(type='str', no_log=True),
            allow_http=dict(type='bool', required=False, default=False),
            validate_certs=dict(type='bool', required=False, default=True),
            state=dict(type='str', required=False, default='present', choices=['present', "absent"]),
            stream_id=dict(type='str'),
            stream_name=dict(type='str'),
            rule_id=dict(type='str'),
            title=dict(type='str'),
            field=dict(type='str'),
            type=dict(type='int', default=1),
            value=dict(type='str'),
            index_set_id=dict(type='str'),
            inverted=dict(type='bool', default=False),
            description=dict(type='str'),
            remove_matches_from_default_stream=dict(type='bool', default=False),
            matching_type=dict(type='str'),
            rules=dict(type='list')
        )
    )

    graylog_user = module.params['graylog_user']
    graylog_password = module.params['graylog_password']
    allow_http = module.params['allow_http']
    endpoint = endpoint_normalize(module.params['endpoint'], allow_http)
  

    state = module.params['state']
    human_url = ""

    api_token = get_token(module, endpoint, graylog_user, graylog_password)
    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json", \
                "Authorization": "Basic ' + api_token.decode() + '" }'

    if state == "present":
        status, message, content, url, is_changed = create_or_update(module, endpoint, headers)
        start(module, endpoint, headers)
        human_url = endpoint + "/streams/" + query_streams(module, endpoint, headers, module.params['title']) + "/search"
    elif state == "absent":
        status, message, content, url, is_changed = delete(module, endpoint, headers)

    uresp = {}
    content = to_text(content, encoding='UTF-8')

    try:
        js = json.loads(content)
    except ValueError:
        js = ""
    
    uresp['json'] = js
    uresp['status'] = status
    uresp['msg'] = message
    uresp['url'] = url
    uresp['human_url'] = human_url
    uresp['changed'] = is_changed
    module.exit_json(**uresp)


if __name__ == '__main__':
    main()
