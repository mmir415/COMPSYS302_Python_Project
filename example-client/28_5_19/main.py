#!/usr/bin/python3
""" main.py

    COMPSYS302 - Software Design - Example Client Webapp
    Current Author/Maintainer: Hammond Pearce (hammond.pearce@auckland.ac.nz)
    Last Edited: March 2019

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 18.0.1  (www.cherrypy.org)
#            Python  (We use 3.5.x +)

import os

import cherrypy

import server

import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils
import time
import socket

host_name = socket.gethostname()
print(host_name, type(host_name))
ip = socket.gethostbyname(host_name)
# The address we listen for connections on
#LISTEN_IP = "172.23.155.225"
#Below is the uni IP
#LISTEN_IP = "172.23.134.246"

#Below is the home IP
LISTEN_IP = "172.23.134.246"
#LISTEN_IP = ip
LISTEN_PORT = 81

def runMainApp():
    #set up the config
    conf = {
        '/': {
            'tools.staticdir.root': os.getcwd(),
            'tools.encode.on': True, 
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on': True,
            'tools.sessions.timeout': 60 * 1, #timeout is in minutes, * 60 to get hours

            # The default session backend is in RAM. Other options are 'file',
            # 'postgres', 'memcached'. For example, uncomment:
            # 'tools.sessions.storage_type': 'file',
            # 'tools.sessions.storage_path': '/tmp/mysessions',
        },

        #configuration for the static assets directory
        '/static': { 
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
        },
        
        #once a favicon is set up, the following code could be used to select it for cherrypy
        #'/favicon.ico': {
        #    'tools.staticfile.on': True,
        #    'tools.staticfile.filename': os.getcwd() + '/static/favicon.ico',
        #},
    }

    cherrypy.site = {
        'base_path': os.getcwd()
    }

    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(server.MainApp(), "/", conf)
    cherrypy.tree.mount(server.apiList(), "/api/", conf)

    # Tell cherrypy where to listen, and to turn autoreload on
    cherrypy.config.update({'server.socket_host': LISTEN_IP,
                            'server.socket_port': LISTEN_PORT,
                            'engine.autoreload.on': True,
                           })

    #cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99)

    print("========================================")
    print("             Hassaan Mirza")
    print("         University of Auckland")
    print("   COMPSYS302 - Example client web app")
    print("========================================")                       
    
    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()

 
#Run the function to start everything
if __name__ == '__main__':
    runMainApp()
