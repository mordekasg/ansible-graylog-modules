
#!/usr/bin/python
# -*- coding: utf-8 -*-


from ansible.module_utils.urls import fetch_url 
from ansible.module_utils._text import to_text
import base64
import json


def compare_dict( dict_one, dict_two ):
  if dict_one.keys() != dict_two.keys():
    return False

  for one_key in dict_one.keys():
    if dict_one[one_key] != dict_two[one_key]:
      return False
  
  return True

def get_token(module, endpoint, username, password):

  headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json" }'

  payload = {
      'username': username,
      'password': password,
      'host': endpoint
  }

  response, info = fetch_url(
    module=module, 
    url=endpoint + "/api/system/sessions", 
    headers=json.loads(headers), 
    method='POST', 
    data=module.jsonify(payload)
    )

  if info['status'] != 200:
    # raise Exception(info)
    module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

  try:
    content = to_text(response.read(), errors='surrogate_or_strict')
    session = json.loads(content)
  except AttributeError:
    content = info.pop('body', '')

  session_string = session['session_id'] + ":session"
  session_bytes = session_string.encode('utf-8')
  session_token = base64.b64encode(session_bytes)

  return session_token


def endpoint_normalize(endpoint_adress, allow_http):
    if not endpoint_adress.startswith("htt"):
      if allow_http == True:
        endpoint_adress = "http://" + endpoint_adress
      else:
        endpoint_adress = "https://" + endpoint_adress

    return endpoint_adress


def work_request( module, url, headers, http_method, success_codes, data=None):

    response, info = fetch_url(module=module, url=url, headers=headers, method=http_method, data=data)
    
    if info['status'] not in success_codes:
      module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))
    try:
      content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
      content = info.pop('body', '')
    return info['status'], info['msg'], content, url
