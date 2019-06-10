import urllib.request
import json
import base64
import cherrypy
import nacl.encoding
import nacl.signing
import nacl.utils
import time

username = "mmir415"
password = "mmir415_339816700"
key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
timing = str(time.time())

received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
message = received_data.get('message').encode('utf-8')
print("Broadcast:")
print(message)

response = {
    'response : ok'
}

response = json.dumps(response)


