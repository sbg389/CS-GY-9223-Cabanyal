import json
from dnstwist import dnstwist
import json
import requests
import datetime
import hashlib
import hmac
import base64
import os

_originalDomain = os.environ['ORIGINALDOMAINNAME']
_wks_id = os.environ['WKSID']
_wks_shared_key = os.environ['WKSSHAREDKEY']

event = {
        "ClientCode": "ABC0",
        "OriginalDomain": _originalDomain,
        "local": True
    }


#Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
  method = 'POST'
  content_type = 'application/json'
  resource = '/api/logs'
  rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
  content_length = len(body)
  signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
  uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

  headers = {
      'content-type': content_type,
      'Authorization': signature,
      'Log-Type': log_type,
      'x-ms-date': rfc1123date
  }

  response = requests.post(uri,data=body, headers=headers)
  if (response.status_code >= 200 and response.status_code <= 299):
      print ('Accepted')
  else:
      print ("Response code: {}".format(response.text))

def createLogEntry(originalDomain, squattedDomain, records):
    #Retrieve your Log Analytics Workspace ID from your Key Vault Databricks Secret Scope
    #wks_id = dbutils.secrets.get(scope = "keyvault_scope", key = "wks-id-logaw")
    wks_id = _wks_id
    log_type = 'NYUINCIDENT'

    #An example JSON log entry
    json_data = [{
    "domain" : originalDomain,
    "squattedDomain": squattedDomain,
    "MX_record": records,
    "IsActive": "true"
    }]
    body = json.dumps(json_data)

    #Retrieve your Log Analytics Primary Key from your Key Vault Databricks Secret Scope
    wks_shared_key = _wks_shared_key
    body = json.dumps(json_data)

    post_data (wks_id, wks_shared_key,body, log_type)

#Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
  x_headers = 'x-ms-date:' + date
  string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
  bytes_to_hash = str.encode(string_to_hash,'utf-8')  
  decoded_key = base64.b64decode(shared_key)
  encoded_hash = (base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())).decode()
  authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
  return authorization

def runDnsTwist():

    try:
        import queue
    except ImportError:
        import Queue as queue

    # Other imports
    import datetime as DT
    import json
    import logging
    import os
    import sys
    import time

    domain = event["OriginalDomain"]

    print("Cabanyal started //--------------------")
    print("Running dnstwist for domain: " + domain)

    url = dnstwist.UrlParser(domain)

    dfuzz = dnstwist.Fuzzer(domain)
    dfuzz.generate()
    domains = dfuzz.domains
        
    print("Processing %d domain variants " % len(domains))
    print("----------------------------------------")

    jobs = queue.Queue()

    global threads
    threads = []

    # Old Code: Set is not iterable
    # for i in range(len(domains)):
    #    jobs.put(domains[i])

    for val in domains:
        jobs.put(val)

    for i in range(dnstwist.THREAD_COUNT_DEFAULT*20):
        worker = dnstwist.Scanner(jobs)
        worker.setDaemon(True)

        worker.uri_scheme = url.scheme
        worker.uri_path = url.path
        worker.uri_query = url.query
        #worker.option_mxcheck = True

        worker.domain_orig = url.domain

        worker.start()
        threads.append(worker)
        
    qperc = 0
    while not jobs.empty():
        #LOGGER.info('.')
        qcurr = 100 * (len(domains) - jobs.qsize()) / len(domains)
        if qcurr - 15 >= qperc:
            qperc = qcurr
            time.sleep(1)

    for worker in threads:
        worker.stop()
        worker.join()

    hits_total = sum('dns-ns' in d or 'dns-a' in d for d in domains)
    hits_percent = 100 * hits_total / len(domains)

    #print(domains)
    #Iterate and process MX entries for the permuatations
    it = iter(domains)
    while True:
        try:
            x = next(it)
        except StopIteration:
            break
        else:
            if 'dns_mx' in x.keys():
                if (x['domain']!=domain):
                    print ('[ALERT]:' + str(x['domain']) + ' MX:' + str(x['dns_mx']))
                    #Post the log
                    createLogEntry(domain,str(x['domain']), str(x['dns_mx']))
                    
def lambda_handler(event, context):
    # TODO implement
    runDnsTwist()
    return {
        'statusCode': 200,
        'body': json.dumps('DNSTwist Job launched!')
    }

