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


def get_input_data_by_id(module, base_url, headers, id):

  url = "{base_url}/api/system/inputs/{id}".format(base_url=base_url, id=id)
  response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')
  try:
    content = to_text(response.read(), errors='surrogate_or_strict')
    data = json.loads(content)
  except AttributeError:
    content = info.pop('body', '')
    data = None

  return data

def search_by_name(module, base_url, headers, title):

  url = base_url + "/api/system/inputs/"
  inputExist = False

  response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

  if info['status'] != 200:
    module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

  try:
    content = to_text(response.read(), errors='surrogate_or_strict')
    data = json.loads(content)
  except AttributeError:
    content = info.pop('body', '')

  regex = r"^" + re.escape(title) + r"$"

  for graylogInputs in data['inputs']:
    if re.match(regex, graylogInputs['title']) is not None:
      inputExist = True
  
  return inputExist

def search_by_port(module, base_url, headers, port):

  url = base_url + "/api/system/inputs/"
  inputExist = False
  response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')
  if info['status'] != 200:
    module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))
  try:
    content = to_text(response.read(), errors='surrogate_or_strict')
    data = json.loads(content)
  except AttributeError:
    content = info.pop('body', '')
  for graylogInputs in data['inputs']:
    # print(graylogInputs)
    if graylogInputs['attributes']['port'] == port:
      module.params['input_id'] = graylogInputs['id']
      inputExist = True
  return inputExist

def start_input(module, base_url, headers, input_id):
  return work_request(
    module=module,
    url="{base_url}/api/cluster/inputstates/{input_id}".format(base_url=base_url, input_id=input_id),
    headers=json.loads(headers),
    http_method="PUT",
    data=None,
    success_codes=[200]
  )

def action(module, base_url, headers):
  inputExist = search_by_port(module, base_url, headers, module.params['port'])
  
  if inputExist:
    data_pre = get_input_data_by_id(module, base_url, headers, module.params['input_id'])
    url = base_url + "/api/system/inputs/" + module.params['input_id']
  else:
    data_pre = {}
    url = base_url + "/api/system/inputs/"
 
  if inputExist and module.params['state'] == "present":
    httpMethod = "PUT"
  elif module.params['state'] == "absent":
    if inputExist == False:
      module.exit_json(changed=False)
      return "200", "Wasn`t present", "", base_url
    httpMethod = "DELETE"
  else:
    httpMethod = "POST"
 
  configuration = {}
  for key in [ 'bind_address', 'port', 'number_worker_threads', 'override_source', 'recv_buffer_size', \
               'tcp_keepalive', 'tls_enable', 'tls_cert_file', 'tls_key_file', 'tls_key_password', \
               'tls_client_auth', 'tls_client_auth_cert_file', 'use_null_delimiter', 'decompress_size_limit', \
               'enable_cors', 'idle_writer_timeout', 'max_chunk_size', 'max_message_size' ]:
      if module.params[key] is not None:
          configuration[key] = module.params[key]
 
  payload = {}
  payload['type'] = module.params['input_type']
  payload['title'] = module.params['title']
  payload['global'] = module.params['global_input']
  payload['node'] = module.params['node']
  payload['configuration'] = configuration
 
  status, msg, content, url = work_request(
    module=module,
    url = url,
    headers=json.loads(headers),
    http_method=httpMethod,
    data=module.jsonify(payload) if httpMethod != "DELETE" else None,
    success_codes=[200, 201, 204]
  )
 
  if module.params['state'] == "present":
    input_id = json.loads(content)['id']
    module.params['input_id'] = input_id
 
    data_post = get_input_data_by_id(module, base_url, headers, input_id )
 
    data_post['created_at'] = data_pre['created_at'] = ""
    status, message, content, url = start_input(module, base_url, headers, input_id )
    module.exit_json(changed= not compare_dict(data_pre, data_post))
  else:
    module.exit_json(changed=True)
 
  return status, msg, content, url


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
            input_type=dict(type='str', required=False, default='UDP',
                        choices=[ 'UDP', 'TCP', 'HTTP' ]),
            title=dict(type='str', required=True ),
            global_input=dict(type='bool', required=False, default=True),
            node=dict(type='str', required=False),
            bind_address=dict(type='str', required=False, default='0.0.0.0'),
            input_id=dict(type='str', required=False, default=''),
            port=dict(type='int', required=False, default=12201),
            number_worker_threads=dict(type='int', required=False, default=2),
            override_source=dict(type='str', required=False),
            recv_buffer_size=dict(type='int', required=False, default=1048576),
            tcp_keepalive=dict(type='bool', required=False, default=False),
            tls_enable=dict(type='bool', required=False, default=False),
            tls_cert_file=dict(type='str', required=False),
            tls_key_file=dict(type='str', required=False),
            tls_key_password=dict(type='str', required=False, no_log=True),
            tls_client_auth=dict(type='str', required=False, default='disabled',
                        choices=[ 'disabled', 'optional', 'required' ]),
            tls_client_auth_cert_file=dict(type='str', required=False),
            use_null_delimiter=dict(type='bool', required=False, default=False),
            decompress_size_limit=dict(type='int', required=False, default=8388608),
            enable_cors=dict(type='bool', required=False, default=True),
            idle_writer_timeout=dict(type='int', required=False, default=60),
            max_chunk_size=dict(type='int', required=False, default=65536),
            max_message_size=dict(type='int', required=False, default=2097152),
            static_fields=dict(type='dict', required=False, default={} )
        )
    )


  graylog_user = module.params['graylog_user']
  graylog_password = module.params['graylog_password']
  allow_http = module.params['allow_http']
  endpoint = endpoint_normalize(module.params['endpoint'], allow_http)
  
  # Build full name of input type
  if module.params['input_type'] == "TCP":
      module.params['input_type'] = "org.graylog2.inputs.gelf.tcp.GELFTCPInput"
  elif module.params['input_type'] == "UDP":
      module.params['input_type'] = "org.graylog2.inputs.gelf.udp.GELFUDPInput"
  else:
      module.params['input_type'] = "org.graylog2.inputs.gelf.http.GELFHttpInput"
  
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
