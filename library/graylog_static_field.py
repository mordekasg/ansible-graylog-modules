#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Matthieu SIMON
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_text
import sys, os, re, json, base64
from ansible.module_utils.graylog_helpers import *

def start_input(module, base_url, headers):

    input_id = module.params['input_id']
    url = "{base_url}/api/cluster/inputstates/{input_id}".format(base_url=base_url, input_id=input_id)

    response, info = fetch_url(
        module=module,
        url=url,
        headers=json.loads(headers),
        method="PUT"
    )

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    return info['status']



def get_input_data_by_id(module, base_url, headers, id):
  
  url = "{base_url}/api/system/inputs/{id}".format(base_url=base_url, id=id)
  response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

  try:
    content = to_text(response.read(), errors='surrogate_or_strict')
    data = json.loads(content)
    if "static_fields" in data.keys():
      data = data["static_fields"]
  except AttributeError:
    content = info.pop('body', '')
    data = {}

  return data


def action(module, base_url, headers):

  if module.params['state'].lower() == "absent":
    httpMethod = "DELETE"
  elif module.params['state'].lower() == "present":
    httpMethod = "POST"
  else: 
    httpMethod = "POST"

  data_pre = get_input_data_by_id(module, base_url, headers, module.params['input_id'])
  
  url = base_url + "/api/system/inputs/" + module.params['input_id'] + "/staticfields"

  for x in module.params['static_fields'].keys():

    if module.params['state'].lower() == "absent":
        url = base_url + "/api/system/inputs/" + module.params['input_id'] + "/staticfields/" + x

    response, info = fetch_url(
        module=module, 
        url=url, 
        headers=json.loads(headers), 
        method=httpMethod, 
        data=module.jsonify( 
          {
            "key": x,
            "value": module.params['static_fields'][x]
          }
         ) if httpMethod != "DELETE" else None
        )

    if info['status'] not in [200, 201, 204, 404]:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

  data_post = get_input_data_by_id(module, base_url, headers, module.params['input_id'])

  if module.params['state'] == "present":
    status = start_input(module, base_url, headers)

  module.exit_json(changed= not compare_dict(data_pre, data_post) )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            endpoint=dict(type='str'),
            graylog_user=dict(type='str'),
            graylog_password=dict(type='str', no_log=True),
            validate_certs=dict(type='bool', required=False, default=True),
            allow_http=dict(type='bool', required=False, default=False),
            state=dict(type='str', required=False, default='present',
                        choices=[ 'present', 'absent' ]),
            input_id=dict(type='str', required=True),
            static_fields=dict(type='dict', required=False, default={} )
        )
    )

    graylog_user = module.params['graylog_user']
    graylog_password = module.params['graylog_password']
    allow_http = module.params['allow_http']
    endpoint = endpoint_normalize(module.params['endpoint'], allow_http)


    api_token = get_token(module, endpoint, graylog_user, graylog_password)
    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json", \
                "Authorization": "Basic ' + api_token.decode() + '" }'

    status, message, content, url = action(module, endpoint, headers)


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

    module.exit_json(**uresp)


if __name__ == '__main__':
    main()
