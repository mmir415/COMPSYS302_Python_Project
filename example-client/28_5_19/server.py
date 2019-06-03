import cherrypy
import urllib.request
import nacl.encoding
import nacl.signing
import nacl.utils
import base64
import time
import json
#from example_client import ping

startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"

key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
timing = str(time.time())

class apiList(object):
    
	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }      
    @cherrypy.expose              
    def rx_broadcast(self):
        received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))

        message = received_data.get('message').encode('utf-8')
        print("Broadcast:")
        print(message)

        response = {
            'response':'ok'
        }
        response = json.dumps(response)
        return (response)


   



class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "Welcome to Yacker!<br/>"
        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Vae victus! <a href='/signout'>Sign out</a>"
        except KeyError: #There is no username
            
            Page += "Click here to <a href='login'>login</a>."
        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="password" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = MainApp.ping(self,username, password)
        if error == 0:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            MainApp.report(self,username,password)

            for x in  (MainApp.listusers(self,username,password))["users"]:
                try:
                    ip_address = x.get("connection_address")
                    print(ip_address)
                    MainApp.broadcast(self,username,ip_address,password)
                except:
                    pass
            #MainApp.listusers(self,username,password)
            
                
            MainApp.receive_message(self)
            
            
        #    pubkeyAutho()
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')
    @cherrypy.expose
    def report(self,username,password):

    # Serialize the verify key to send it to a third party
            signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
            verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
            pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
            credentials = ('%s:%s' % (username, password))
            b64_credentials = base64.b64encode(credentials.encode('ascii'))
            headers = {
                'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
                'Content-Type' : 'application/json; charset=utf-8',
            }
            pubkey_hex_str = pubkey_hex.decode('utf-8')

            message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
            signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

            signature_hex_str = signed.signature.decode('utf-8')

            addkey_url = "http://cs302.kiwi.land/api/report"

            payload = {
                "connection_location": "2",
                "connection_address": "172.23.134.246:80",
                "incoming_pubkey": pubkey_hex_str
        
            }
            json_payload = json.dumps(payload)
            byte_payload = bytes(json_payload, "utf-8")

            try:   
                req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
                response = urllib.request.urlopen(req)
            except urllib.error.HTTPError as err:
                print("Error: " + str(err.code))
            else:
                data = response.read() # read the received bytes
                encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
                response.close()

                JSON_object = json.loads(data.decode(encoding))
                print(JSON_object)

    @cherrypy.expose
    def ping(self,username,password):

     # Serialize the verify key to send it to a third party
        signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
        verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
        pubkey_hex_str = pubkey_hex.decode('utf-8')
   
        message_bytes = bytes(pubkey_hex_str, encoding='utf-8')
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

        signature_hex_str = signed.signature.decode('utf-8')

        addkey_url = "http://cs302.kiwi.land/api/ping"

        #create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "pubkey": pubkey_hex_str,
            #"username": username,
            "signature": signature_hex_str,
        }
        json_payload = json.dumps(payload)
        byte_payload = bytes(json_payload, "utf-8")

        try:   
            req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
            response = urllib.request.urlopen(req)
        except urllib.error.HTTPError as err:
            print("Error: " + str(err.code))
        else:
            data = response.read() # read the received bytes
            encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
            response.close()

            JSON_object = json.loads(data.decode(encoding))
            if (JSON_object["authentication"] == "error"):
                return 1
            else:
                print(json.dumps(JSON_object,indent=4))
                return 0
    @cherrypy.expose
    def listusers(self,username,password):
        
        addkey_url = "http://cs302.kiwi.land/api/list_users"
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }

        #create request and open it into a response object
        req = urllib.request.Request(url=addkey_url, headers=headers)
        response = urllib.request.urlopen(req)
        #read and process the received bytes

        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()

        JSON_object = json.loads(data.decode(encoding))
        print(json.dumps(JSON_object,indent=4))
        return (JSON_object)
        #for x in JSON_object["users"]:
        #    print(x["username"])


    @cherrypy.expose    
    def get_privatedata(self,username,password):

        addkey_url = "http://cs302.kiwi.land/api/get_privatedata"
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }
    
    #create request and open it into a response object

    #read and process the received bytes

    #create request and open it into a response object
        try:
            req = urllib.request.Request(url=addkey_url, headers=headers)
            response = urllib.request.urlopen(req)

        except urllib.error.HTTPError as err:
            print("Error: " + str(err.code))
        else:
            data = response.read() # read the received bytes
            encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
            response.close()

            JSON_object = json.loads(data.decode(encoding))
            if JSON_object["privatedata"] == "7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5":
                print(json.dumps(JSON_object,indent=4))
                return JSON_object["privatedata"]

            else:
                return 1

    @cherrypy.expose
    def broadcast(self,username,ip_address,password):
        timing = str(time.time())
        ENCODING = 'utf-8'

        login_server_record = 'mmir415,7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,1558398219.422035,5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c'
        signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)

        # Serialize the verify key to send it to a third party
    #verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
        
        pubkey_hex_str = pubkey_hex.decode(ENCODING)

        message = "How much wood could a wood chuck chuck if a woodchuck could chuck wood"

        message_bytes = bytes(login_server_record + message + timing, encoding=ENCODING)
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

        signature_hex_str = signed.signature.decode(ENCODING)

        addkey_url = "http://"+ip_address+"/api/rx_broadcast"

        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "loginserver_record": login_server_record,
            "message": message,
            "sender_created_at": timing,
            "signature": signature_hex_str
        }
        json_payload = json.dumps(payload)
        byte_payload = bytes(json_payload, ENCODING)

        try:   
            req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
            response = urllib.request.urlopen(req)
        except urllib.error.HTTPError as err:
            print("Error: " + str(err.code))
        else:
            data = response.read() # read the received bytes
            encoding = response.info().get_content_charset(ENCODING) #load encoding if possible (default to utf-8)
            response.close()

            JSON_object = json.loads(data.decode(encoding))
            print(JSON_object)

            # received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
            response = JSON_object.get('response')
            print("Broadcast:")
            print(response)

            # response = {
            # 'response : ok'
            # }

            # response = json.dumps(response)
            # print(response)

    @cherrypy.expose
    def receive_message(self):
        print("Sending message")


    
# def authoriseUserLogin(username, password):
#     print("Log on attempt from {0}:{1}".format(username, password))
#     #ping(username,password)
#     pubhexstr = (MainApp.get_privatedata(username = username,password = password))
#     # report(username,password)
#     return (MainApp.ping(username,password))



###
### Functions only after here
###
def pubkeyAutho():
    signing_key = nacl.signing.SigningKey.generate()

    username = cherrypy.session['username']
    password = cherrypy.session['password']

    # Serialize the verify key to send it to a third party
    verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex = signing_key.verify_key_hex.encode(encoder = nac1.encoding.HexEncoder)
    
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

    signature_hex_str = signed.signature.decode('utf-8')

    addkey_url = "http://cs302.kiwi.land/api/add_pubkey?pubkey="+pubkey_hex_str

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

    payload = {
     "pubkey": pubkey_hex_str,
     "username": username,
     "signature": signature_hex_str,
}
    json_payload = json.dumps(payload)
    byte_payload = bytes(json_payload, "utf-8")



   # try:
   #     req = urllib.request.Request(addkey_url, data=byte_payload, headers=headers)
   #    response = urllib.request.urlopen(req)
   #     data = response.read() # read the received bytes
   #     encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
   #     response.close()

   # except urllib.error.HTTPError as error:
    
   #     print(error.read())
   #     exit()

   # JSON_object = json.loads(data.decode(encoding))
   # if (JSON_object["response"] == "ok"):
   #     print("PUBKEY SUCC")
   #     cherrypy.session['signing_key'] = signing_key
   #     return 0
   # else:
   #     print ("Fail")
   #     return 1pubk
# @cherrypy.expose
# def listusers(username,password):
    
#     addkey_url = "http://cs302.kiwi.land/api/list_users"
#     credentials = ('%s:%s' % (username, password))
#     b64_credentials = base64.b64encode(credentials.encode('ascii'))
#     headers = {
#         'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#         'Content-Type' : 'application/json; charset=utf-8',
#     }

#     #create request and open it into a response object
#     req = urllib.request.Request(url=addkey_url, headers=headers)
#     response = urllib.request.urlopen(req)
#     #read and process the received bytes

#     data = response.read() # read the received bytes
#     encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
#     response.close()

#     JSON_object = json.loads(data.decode(encoding))
#     print(json.dumps(JSON_object,indent=4))


# @cherrypy.expose    
# def get_privatedata(username,password):

#     addkey_url = "http://cs302.kiwi.land/api/get_privatedata"
#     credentials = ('%s:%s' % (username, password))
#     b64_credentials = base64.b64encode(credentials.encode('ascii'))
#     headers = {
#         'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#         'Content-Type' : 'application/json; charset=utf-8',
#     }
 
# #create request and open it into a response object

# #read and process the received bytes

# #create request and open it into a response object
#     try:
#         req = urllib.request.Request(url=addkey_url, headers=headers)
#         response = urllib.request.urlopen(req)

#     except urllib.error.HTTPError as err:
#         print("Error: " + str(err.code))
#     else:
#         data = response.read() # read the received bytes
#         encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
#         response.close()

#         JSON_object = json.loads(data.decode(encoding))
#         if JSON_object["privatedata"] == "7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5":
#             print(json.dumps(JSON_object,indent=4))
#             return JSON_object["privatedata"]

#         else:
#             return 1

# @cherrypy.expose
# def broadcast(username,password):
#     timing = str(time.time())
#     ENCODING = 'utf-8'

#     login_server_record = 'mmir415,7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,1558398219.422035,5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c'
#     signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)

#     # Serialize the verify key to send it to a third party
# #verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
#     pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
#     pubkey_hex_str = pubkey_hex.decode(ENCODING)

#     message = "Hello there"

#     message_bytes = bytes(login_server_record + message + timing, encoding=ENCODING)
#     signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

#     signature_hex_str = signed.signature.decode(ENCODING)

#     addkey_url = "http://172.23.155.225:80/api/rx_broadcast"

#     credentials = ('%s:%s' % (username, password))
#     b64_credentials = base64.b64encode(credentials.encode('ascii'))
#     headers = {
#         'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#         'Content-Type' : 'application/json; charset=utf-8',
#     }

#     payload = {
#         "loginserver_record": login_server_record,
#         "message": message,
#         "sender_created_at": timing,
#         "signature": signature_hex_str
#     }
#     json_payload = json.dumps(payload)
#     byte_payload = bytes(json_payload, ENCODING)

#     try:   
#         req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
#         response = urllib.request.urlopen(req)
#     except urllib.error.HTTPError as err:
#         print("Error: " + str(err.code))
#     else:
#         data = response.read() # read the received bytes
#         encoding = response.info().get_content_charset(ENCODING) #load encoding if possible (default to utf-8)
#         response.close()

#         JSON_object = json.loads(data.decode(encoding))
#         print(JSON_object)

#         # received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
#         response = JSON_object.get('response')
#         print("Broadcast:")
#         print(response)

#         # response = {
#         # 'response : ok'
#         # }

#         # response = json.dumps(response)
#         # print(response)

# @cherrypy.expose
# def receive_message(self):
#     print("receiving message")


# @cherrypy.expose
# def report(username,password):

#     # Serialize the verify key to send it to a third party
#     signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
#     verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
#     pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
#     credentials = ('%s:%s' % (username, password))
#     b64_credentials = base64.b64encode(credentials.encode('ascii'))
#     headers = {
#         'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#         'Content-Type' : 'application/json; charset=utf-8',
#     }
#     pubkey_hex_str = pubkey_hex.decode('utf-8')

#     message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
#     signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

#     signature_hex_str = signed.signature.decode('utf-8')

#     addkey_url = "http://cs302.kiwi.land/api/report"

#     payload = {
#         "connection_location": "2",
#         "connection_address": "172.23.155.225",
#         "incoming_pubkey": pubkey_hex_str
    
#     }
#     json_payload = json.dumps(payload)
#     byte_payload = bytes(json_payload, "utf-8")

#     try:   
#         req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
#         response = urllib.request.urlopen(req)
#     except urllib.error.HTTPError as err:
#         print("Error: " + str(err.code))
#     else:
#         data = response.read() # read the received bytes
#         encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
#         response.close()

#         JSON_object = json.loads(data.decode(encoding))
#         print(JSON_object)





    
   # if ((username.lower() == "user") and (password.lower() == "password") or (username.lower() == "mmir415") and (password.lower() == "mmir415_339816700") ):
  
     #   print("Success")
    #return 0
   # else:
   #     print("Failure")
   #     return 1
