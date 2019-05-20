import urllib.request
import json
import base64

url = "http://cs302.kiwi.land/api/report"

#STUDENT TO UPDATE THESE...
username = "mmir415"
password = "mmir415_339816700"

#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

payload = {
     "connection_location": "2",
     "connection_address": "172.23.136.2" 
}

#STUDENT TO COMPLETE:
#1. convert the payload into json representation, 
#2. ensure the payload is in bytes, not a string
json_payload = json.dumps(payload)
byte_payload = bytes(json_payload, "utf-8")

#3. pass the payload bytes into this function
req = urllib.request.Request(url, data=byte_payload, headers=headers)
response = urllib.request.urlopen(req)

data = response.read() # read the received bytes
encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
response.close()

JSON_object = json.loads(data.decode(encoding))
print(JSON_object)
