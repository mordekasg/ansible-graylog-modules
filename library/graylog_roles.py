#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# # Copyright: (c) 2019, Whitney Champion <whitney.ellis.champion@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

# import module snippets

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, to_text
import urllib
import sys, os, re, json, base64
from ansible.module_utils.graylog_helpers import *


module = None
base_url = None
headers = None
SUCCESS_CODES= [200, 201, 204]


def role_exists(role_name):  
  response, info = fetch_url(module=module, url=base_url + urllib.quote( "/" + role_name ), headers=json.loads(headers), method='GET')
  return info['status'] == 200


def present():

  if role_exists( module.params['name'] ):
    http_method = "PUT"
    url = base_url + urllib.quote( "/" + module.params['name'] )
  else:
    http_method = "POST"
    url = base_url

  payload = {}
  for key in ['name', 'description', 'permissions', 'read_only']:
    if module.params[key] is not None:
      payload[key] = module.params[key]
  
  return work_request(
    module = module,
    url=url,
    headers=json.loads(headers),
    http_method=http_method,
    data=module.jsonify(payload),
    success_codes=SUCCESS_CODES
  )



def absent():

  return work_request(
    module = module,
    url=base_url + urllib.quote( "/" + module.params['name'] ),
    headers=headers,
    http_method='DELETE',
    success_codes=SUCCESS_CODES
  )


def list():

  url = base_url
  response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')
  
  return work_request(
    module = module,
    url=url,
    headers=headers,
    http_method='GET',
    success_codes=SUCCESS_CODES
  )


def main():
  global module, base_url, headers
  module = AnsibleModule(
      argument_spec=dict(
      endpoint=dict(type='str'),
      graylog_user=dict(type='str'),
      graylog_password=dict(type='str', no_log=True),
      allow_http=dict(type='bool', required=False, default=False),
      validate_certs=dict(type='bool', required=False, default=True),
      state=dict(type='str', default='list', choices=['present', 'absent', 'list']),
      name=dict(type='str'),
      description=dict(type='str'),
      permissions=dict(type='list'),
      read_only=dict(type='str', default="false")
    )
  )

  graylog_user = module.params['graylog_user']
  graylog_password = module.params['graylog_password']
  allow_http = module.params['allow_http']
  endpoint = endpoint_normalize(module.params['endpoint'], allow_http)
    
  
  api_token = get_token(module, endpoint, graylog_user, graylog_password)
  
  headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json", \
              "Authorization": "Basic ' + api_token.decode() + '" }'
  base_url = endpoint + "/api/roles"
  
  if  module.params['state'] == "present":
    status, message, content, url = present()
  elif module.params['state'] == "absent":
    status, message, content, url = absent()
  elif module.params['state'] == "list":
    status, message, content, url = list()
  
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
