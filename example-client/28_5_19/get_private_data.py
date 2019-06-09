import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils
import nacl.secret
import nacl.pwhash.argon2i

addkey_url = "http://cs302.kiwi.land/api/get_privatedata"

# username = "mmir415"
# password = "mmir415_339816700"
username = "keva419"
password = "KimberleyEvans-Parker_576292546"


key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

#Results after first usage
#{'loginserver_record': 'mmir415,(username)
#7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,(pubkey)
#1558398219.422035,(time)
#5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c'} (signature)
#The public key provided in the message should be derived from the private key used to sign the message (i.e. what is used to create X-signature HTTP header) 
 

#encrypted_data = "MJV2FB1Lic7tPoeIzoW+5G9r3hPH9wemE408eMY50dG2Kiu/N3DkcRhpNEyI78tRLOJqMVKbgpo7Y58QsLNlkgm42zph1BzQpcUchvVmaTinUTJ6XgFlEJHnDerWF7ygP7VxZtCS95KKmILRnfBx+OQxcCzwoG5xnDFq"

#plaintext = box.decrypt(encrypted_data,encoder = nacl.encoding.Base64Encoder)

#data = plaintext.decode('utf-8')
#print(data)

#create request and open it into a response object
req = urllib.request.Request(url=addkey_url, headers=headers)
response = urllib.request.urlopen(req)
#read and process the received bytes

data_in = response.read() # read the received bytes
encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
response.close()

JSON_object = json.loads(data_in.decode(encoding))
print(json.dumps(JSON_object,indent=4))

password = str(3302)
byte = bytes(password, encoding = 'utf-8')
key_password = password*16
salt = bytes(key_password.encode('utf-8')[:16])
ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
saltBytes = nacl.pwhash.argon2i.SALTBYTES

key = nacl.pwhash.argon2i.kdf(32,byte,salt,ops,mem)
box = nacl.secret.SecretBox(key) #safe used to encrypt/decrypt messages

encrypted_data = str((JSON_object["privatedata"]))


plaintext = box.decrypt(encrypted_data,encoder = nacl.encoding.Base64Encoder)

data = plaintext.decode('utf-8')
print(data)
data = json.loads(data.encode(encoding))
print(data)
print(type(data))
private_keys = (data["prikeys"])
private_key = private_keys[0]
print(private_key)





