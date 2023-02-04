from auxiliary import *

from server import HTTP_Server_RequestHandler #own custom module
from server import ACME_DNS_Resolver
from server import HTTP_Server_RequestHandler_Shutdown

from server import HTTPS_RequestHandler
from http.server import HTTPServer, BaseHTTPRequestHandler #part of standard library

#https://docs.python.org/3.10/library/


import argparse #part of standard library
import requests
import dnslib
from dnslib.server import *
import socket #part of standard library
import socketserver #part of standard library
from socketserver import *
import threading #part of standard library
import ssl #part of standard library
import time #part of standard library

from ACME_Client import *


from base64 import urlsafe_b64encode, urlsafe_b64decode
import json #part of standard library
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import DSS

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from cryptography.hazmat.primitives import serialization

import os #part of standard library
import warnings #part of standard library

'''
- `--dir DIR_URL`
	_(required)_ `DIR_URL` is the directory URL of the ACME server that should be used.
- `--record IPv4_ADDRESS` 
	_(required)_ `IPv4_ADDRESS` is the IPv4 address which must be returned by your DNS server for all A-record queries. 
- `--domain DOMAIN`
	_(required, multiple)_ `DOMAIN`  is the domain for  which to request the certificate. If multiple `--domain` flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., `*.example.net`.
- `--revoke`
	_(optional)_ If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.
'''

#TODO: map all given domains to given IPv4 address via DNs A-record



#TODO
#setup client with functionalities
#
#setup dns-server
#setup https-server
		
def main():
	#https://docs.python.org/3/library/argparse.html#example
	#No need to keep parser, just interestd in args
	args = get_command_line_commands().parse_args()
	
	#debug = args.debug
	if (debug):
		print("Running main.");
		print("Read arguments from commandline: ", end="")
		print(args)
	
	print(20 * "*")
	print("ARGS:")
	print(args)
	print(20 * "*")
	
	#args.challenge_type; rfc8555;8.3/8.4
	#print(args.domain)
	#args.dir
	#args.record
	#args.domain
	#args.revoke
	
	
	#init all servers
	#https://stackoverflow.com/questions/268629/how-to-stop-basehttpserver-serve-forever-in-a-basehttprequesthandler-subclass
	#init http server; change to socket server as it offers a cleaner shutdown command
	#init https server
	#init dns server
	#httpd = HTTPServer(server, HTTP_Server_RequestHandler)
	#server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
	#http://pymotw.com/2/SocketServer/
	#pebble configs: https://blog.xoxzo.com/2020/11/18/root-certificates-generation-using-acme-server-pebble/
	#https://gist.github.com/pklaus/b5a7876d4d2cf7271873
	Challenge_Server_HTTP = ThreadingTCPServer((IP_Address, Challenge_HTTP_PORT), HTTP_Server_RequestHandler)
	thread = threading.Thread(target=Challenge_Server_HTTP.serve_forever)
	thread.daemon = True
	thread.start()
	list_of_servers = [Challenge_Server_HTTP]
	
	DNS_Resolver = ACME_DNS_Resolver(args.domain, args.record)
	
#	dns_mapping_backup = DNS_Resolver.export_hashmap()
	
	#for pebble: 127.0.0.1:
	Server_DNS = DNSServer(resolver = DNS_Resolver, port = DNS_PORT, address = IP_Address)
	Server_DNS.start_thread()
	
	
	
	
#	response = requests.get(url = args.dir, verify="./pebble.minica.pem")
#	print(response)
#	return
	#acme client here
#	if (debug):
	print("INIT ACME_Client")
	#acme_client = ACME_Client(args, "./pebble.minica.pem", HTTP_Server_RequestHandler, HTTPS_Server_RequestHandler, DNS_Resolver)
	acme_client = None
	try:
		acme_client = ACME_Client(args, "./pebble.minica.pem", HTTP_Server_RequestHandler, HTTPS_RequestHandler, DNS_Resolver)
	except Exception as e:
		print("INVALID CERTIFICATE: ", end="")
		print(e)
		return
	
#	if (debug):
	print("END ACME_Client")
	print("INIT create_account")
	acme_client.create_account()
		
#	if (debug):
	print("END create_account")
	print("INIT submit_order")
			
	acme_client.submit_order()
	
#	if (debug):
	print("END submit_order")
	print("INIT process_authorizations_list")
	
	acme_client.process_authorizations_list()
	
#	if (debug):
	print("END process_authorizations_list")
	print("INIT finalize_order")
			
	acme_client.finalize_order()
	
#	if (debug):
	print("END finalize_order")
	print("INIT download_certificate")
	
#	if (debug):
	print("END finalize_order")
	print("INIT download_certificate")
		
	acme_client.download_certificate()
	
#	if (debug):
	print("END download_certificate")
		
	if (args.revoke):
#		if (debug):
		print("CERTIFICATE REVOCATION")
		print("INIT certificate_revocation")	
		acme_client.certificate_revocation()
#		if (debug):
		print("END certificate_revocation")
	
#	if (debug):			
	print("INIT store_certificate_and_key_to_file")	
	acme_client.store_certificate_and_key_to_file()
#	if (debug):	
	print("END store_certificate_and_key_to_file")

				
		
				
	#https://pythontic.com/ssl/sslcontext/wrap_socket
	#https://stackoverflow.com/questions/8582766/adding-ssl-support-to-socketserver
	#https://gist.github.com/newmind/dffd160cfd94a9206c5c
	#https://snyk.io/blog/implementing-tls-ssl-python/
	#https://stackoverflow.com/questions/69909044/python-socket-client-ssl-connection
	#https://docs.python.org/3/library/ssl.html
	#https://docs.micropython.org/en/latest/library/ssl.html
	#https://stackoverflow.com/questions/72112251/python-https-server-stuck-on-ssl-wrap-socket
	#https://stackoverflow.com/questions/61348501/tls-ssl-socket-python-server
	##https://docs.datastax.com/en/developer/python-dse-driver/2.11/security/
	#https://www.electricmonk.nl/log/2018/06/02/ssl-tls-client-certificate-verification-with-python-v3-4-sslcontext/
	#http://erdos.csie.ncnu.edu.tw/~klim/python-docs/library/ssl.html
	#https://pythontic.com/ssl/sslcontext/load_cert_chain
	#https://stackoverflow.com/questions/55660114/python-ssl-standard-library-load-cert-chain-fails-on-loading-pem-cert-chain
	#https://stackoverflow.com/questions/47338790/self-signed-certificate-used-when-wrapping-sockets
	
#	if (debug):
#		print("START HTTPS server")
	
	
#	DNS_Resolver.import_hashmap(dns_mapping_backup)
	
	
	print("START HTTPS server")
	#mainly based on:
	#https://blog.anvileight.com/posts/simple-python-http-server/
	httpd = HTTPServer((IP_Address, Certificate_HTTPS_PORT), HTTPS_RequestHandler)
	
	warnings.filterwarnings("ignore") #surpress warning
	httpd.socket = ssl.wrap_socket(httpd.socket, keyfile = "./keyfile.pem", certfile = './certificate.pem', server_side = True)
	
	#https://stackoverflow.com/questions/268629/how-to-stop-basehttpserver-serve-forever-in-a-basehttprequesthandler-subclass
	
#	while not HTTPS_RequestHandler.has_served_certificate:
#		httpd.handle_request()
	
	#https://www.reddit.com/r/learnpython/comments/ku2gls/is_there_a_stoppable_nonblocking_serve_forever/
	#https://stackoverflow.com/questions/55159072/how-to-stop-a-server-in-python
	thread = threading.Thread(target = httpd.serve_forever)
	thread.daemon = True
	thread.start()
	list_of_servers.append(httpd)
	
#	'''
#	print(20 * "*")
#	print(HTTPS_Server_RequestHandler.certificate)
#	print(20 * "*")
#	#HTTPS_Server_RequestHandler.certificate = b"TEST CERTIFICATE"	
#	
#	Certificate_Server_HTTPS = ThreadingTCPServer((IP_Address, Certificate_HTTPS_PORT), HTTPS_Server_RequestHandler)
#	
#	#context = ssl.create_default_context()
#	context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#	context.load_cert_chain(certfile = "./certificate.pem", keyfile = "./keyfile.key")
##	context.load_cert_chain(certfile = "./certificate.pem", keyfile = "./keyfile.key", password = b"Poorly chosen password")
#	
#	Certificate_Server_HTTPS.socket = context.wrap_socket(Certificate_Server_HTTPS.socket, server_side = True)	
#	thread = threading.Thread(target=Certificate_Server_HTTPS.serve_forever)
#	thread.daemon = True
#	thread.start()
#	list_of_servers.append(Certificate_Server_HTTPS)
#	'''
		
#	if (debug):
#		print("START HTTP shutdown server")
	
	DNS_Resolver.create_A_records(args.domain, args.record)
	
	print("START HTTP shutdown server")
	
	#shutdown all http(s) servers
	#HTTP_Server_RequestHandler_Shutdown.list_of_servers = list_of_servers
	Shutdown_Server_HTTP = ThreadingTCPServer((IP_Address, Shutdown_HTTP_PORT), HTTP_Server_RequestHandler_Shutdown)
	
	thread = threading.Thread(target=Shutdown_Server_HTTP.serve_forever)
	thread.daemon = True
	thread.start()
	
	try:
		os.remove("./shutdown_command") #clean up from previous iterations
	except Exception as e:
		pass
	
	print("WAIT for shutdown command by remote server")
	while True:
		if (debug):
			print("Waiting:")
			#print(HTTP_Server_RequestHandler_Shutdown.received_shutdown_command)
		print("Waiting: ")
		#print(HTTP_Server_RequestHandler_Shutdown.received_shutdown_command)
		try:
			shutdown_file = open("shutdown_command", "r")
			if (shutdown_file.read() != "Shutdown"):
				shutdown_file.close()
				raise ValueError
			shutdown_file.close()
		except Exception as e:
			time.sleep(1.61)
		else:
			break
		
		
	#shutdown all servers
	#https://gist.github.com/tuxfight3r/bfd95575ce34af6bd3317611dc04006c?permalink_comment_id=4004398
	#https://stackoverflow.com/questions/55661626/with-socket-socketsocket-af-inet-socket-sock-stream-as-s-get-error-attribut
	#https://docs.python.org/3/library/socket.html
	#https://www.geeksforgeeks.org/socket-programming-python/
	#https://gist.github.com/pklaus/b5a7876d4d2cf7271873	
	
#	if (debug):
#		print("Shutdown all servers")
	
	print("Shutdown all servers")	
	
	for server in list_of_servers:
		server.shutdown()
	
	Shutdown_Server_HTTP.shutdown()
	
	#shutdown dns server
	Server_DNS.server.server_close()
	Server_DNS.stop()
	
#	if (debug):
#		print("Termination sequence")
	print("Init. Termination sequence")
	
if __name__ == "__main__":
	main()    





