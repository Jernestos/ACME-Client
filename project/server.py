from auxiliary import *

#https://docs.python.org/3/library/time.html#module-time
from time import gmtime, strftime #part of standard library
from http.server import BaseHTTPRequestHandler, HTTPServer #part of standard library
from dnslib.server import *
from dnslib.dns import RR
import socket #part of standard library
import socketserver #part of standard library
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

			
#https://www.data2type.de/xml-xslt-xslfo/xml/python-und-xml/die-python-internet-apis/verwenden-der-serverklassen
#mainly based on:
#https://blog.anvileight.com/posts/simple-python-http-server/
class HTTP_Server_RequestHandler(BaseHTTPRequestHandler):

	key_authorization = None
	
	def myhandler(self):
		self.send_response(200)
		self.send_header("Content-type", "application/octet-stream")
		self.end_headers()
		self.wfile.write(self.key_authorization.encode(encoding = encoding_utf_8))
		if (debug):
			print("HTTP_Server_RequestHandler_Shutdown")

	def do_GET(self):
		self.send_response(200)
		self.send_header("Content-type", "application/octet-stream")
		self.end_headers()
		self.wfile.write(self.key_authorization.encode(encoding = encoding_utf_8))
		if (debug):
			print("HTTP_Server_RequestHandler_Shutdown")
		
	def do_HEAD(self):
		self.send_response(200)
		self.send_header("Content-type", "application/octet-stream")
		self.end_headers()
		self.wfile.write(self.key_authorization.encode(encoding = encoding_utf_8))
		if (debug):
			print("HTTP_Server_RequestHandler_Shutdown")
	
	def do_POST(self):
		self.send_response(200)
		self.send_header("Content-type", "application/octet-stream")
		self.end_headers()
		self.wfile.write(self.key_authorization.encode(encoding = encoding_utf_8))
		if (debug):
			print("HTTP_Server_RequestHandler_Shutdown")
		
			

		
		
		
		
		
	
#https://dnspython.readthedocs.io/en/latest/manual.html
#https://www.dnspython.org/examples.html
#https://www.geeksforgeeks.org/network-programming-in-python-dns-look-up/
#https://blog.devgenius.io/pyops-dnspython-toolkit-590a368b5c2
#Based on tutorial from:
#https://paktek123.medium.com/write-your-own-dns-server-in-python-hosted-on-kubernetes-3febacf33b9b	
#https://gist.github.com/pklaus/b5a7876d4d2cf7271873
class ACME_DNS_Resolver:
	
	def __init__(self, list_of_list_of_domains, record):
		domain_list = DNSName_flattener(list_of_list_of_domains)
		
		record_type_ttl = " 60 A "
		#record_type_ttl = " 300 IN "
		
		dns_record_appendix = record_type_ttl + record[0]
		dns_record_appendix_wih_dot = "." + record_type_ttl + record[0]
		
		self.hashmap = dict()
		
		for domain_name in domain_list:
			if domain_name[-1] != ".":
				self.hashmap[domain_name + "."] = domain_name + dns_record_appendix_wih_dot #with dot
				self.hashmap[domain_name] = domain_name + dns_record_appendix #without dot
			else:
				self.hashmap[domain_name] = domain_name + dns_record_appendix #with dot


#		print("ACME_DNS_Resolver: __init__")
#		print(domain_list)
#		print(record[0])
#		print(self.hashmap)
		
		if (debug):
			print("ACME_DNS_Resolver: __init__")
			print(domain_list)
			print(record[0])
			print(self.hashmap)
			
	def create_A_records(self, list_of_list_of_domains, record):
		domain_list = DNSName_flattener(list_of_list_of_domains)
		
		record_type_ttl = " 60 A "
		
		dns_record_appendix = record_type_ttl + record[0]
		dns_record_appendix_wih_dot = "." + record_type_ttl + record[0]
		
#		self.hashmap = dict()
		
		for domain_name in domain_list:
			if domain_name[-1] != ".":
				self.hashmap[domain_name + "."] = domain_name + dns_record_appendix_wih_dot #with dot
				self.hashmap[domain_name] = domain_name + dns_record_appendix #without dot
			else:
				self.hashmap[domain_name] = domain_name + dns_record_appendix #with dot
				
	
	def export_hashmap(self):
		return self.hashmap
		
	def import_hashmap(self, new_hashmap):
		self.hashmap = new_hashmap
	
	def set_dns_challenge_response(self, key_value, dns_response):
		if (key_value[-1] != "."):
			self.hashmap[key_value] = dns_response
			self.hashmap[key_value + "."] = dns_response
#			self.hashmap["_acme-challenge." + key_value] = dns_response
#			self.hashmap["_acme-challenge." + key_value + "."] = dns_response
		else:
			self.hashmap[key_value] = dns_response
			self.hashmap[key_value[:-1]] = dns_response
#			self.hashmap["_acme-challenge." + key_value] = dns_response
		
#		print("ACME_DNS_Resolver: set_dns_challenge_response")
#		print(self.hashmap)
		
		
	def resolve(self, request, handler):
		
		q_name = str(request.q.qname)
		if (debug):
			print("DNS LOOKUP HAPPENING: ", end="")
			print(q_name)
			print(q_name in self.hashmap.keys())
			print(self.hashmap.keys())
			print(self.hashmap.values())
			#print(self.hashmap)
		
#		print("DNS LOOKUP HAPPENING: ", end="")
#		print(q_name)
#		print(q_name in self.hashmap.keys())
#		print(self.hashmap.keys())
#		print(self.hashmap.values())
		
		#get zone from hashtable from q_name
		
#		if (q_name not in self.hashmap.keys()):
#			print(20 * "0")
#			print("WARNING: DNS RESOLVER ISSUE FOR: ", end="")
#			print(q_name)
#			print(self.hashmap)
#			print(20 * "0")
		
		zone = self.hashmap[q_name]
		
		reply = request.reply()
		reply.add_answer(*RR.fromZone(zone))
		return reply
		








#mainly based on:
#https://blog.anvileight.com/posts/simple-python-http-server/
class HTTP_Server_RequestHandler_Shutdown(BaseHTTPRequestHandler):

	received_shutdown_command = False
	
	def myhandler(self):
		self.send_response(200)
		self.end_headers()
		self.wfile.write(b"")
		self.received_shutdown_command = True
		shutdown_file = open("shutdown_command", "w")
		shutdown_file.write("Shutdown")
		shutdown_file.close()
		print("Shutdown command received. - Init. shutdown.")

	def do_GET(self):
		self.send_response(200)
		self.end_headers()
		self.wfile.write(b"")
		self.received_shutdown_command = True
		shutdown_file = open("shutdown_command", "w")
		shutdown_file.write("Shutdown")
		shutdown_file.close()
		print("Shutdown command received. - Init. shutdown.")
		
	def do_HEAD(self):
		self.send_response(200)
		self.end_headers()
		#self.wfile.write(b"Shutdown command received. - Init. shutdown.")
		self.received_shutdown_command = True
		shutdown_file = open("shutdown_command", "w")
		shutdown_file.write("Shutdown")
		shutdown_file.close()
		print("Shutdown command received. - Init. shutdown.")
	
	def do_POST(self):
		self.send_response(200)
		self.end_headers()
		self.wfile.write(b"")
		self.received_shutdown_command = True
		shutdown_file = open("shutdown_command", "w")
		shutdown_file.write("Shutdown")
		shutdown_file.close()
		print("Shutdown command received. - Init. shutdown.")
		










#from https://gist.github.com/pklaus/b5a7876d4d2cf7271873
#TCPRequestHandler		
#https://stackoverflow.com/questions/32062925/python-socket-server-handle-https-request
#https://pythontic.com/socketserver/tcpserver/introduction	
#mainly based on:
#https://blog.anvileight.com/posts/simple-python-http-server/
class HTTPS_RequestHandler(BaseHTTPRequestHandler):
	
	certificate = None
	has_served_certificate = False
	
	def myhandler(self):
		self.send_response(200)
		self.end_headers()
		self.send_header("Content-type", "application/pem-certificate-chain")
		pebble_certificate_file = open("pebble.minica.pem", "rb")
		pebble_certificate = pebble_certificate_file.read()
		pebble_certificate_file.close()			
		self.wfile.write(self.certificate)
		self.has_served_certificate = True
		print("Certificate request received and served.")

	def do_GET(self):
		self.send_response(200)
		self.send_header("Content-type", "application/pem-certificate-chain")
		self.end_headers()
		
		pebble_certificate_file = open("pebble.minica.pem", "rb")
		pebble_certificate = pebble_certificate_file.read()
		pebble_certificate_file.close()			
		self.wfile.write(self.certificate)
		print(pebble_certificate + self.certificate)
		self.has_served_certificate = True
		print("Certificate request received and served.")
		
	def do_HEAD(self):
		self.send_response(200)
		self.send_header("Content-type", "application/pem-certificate-chain")
		self.end_headers()
		pebble_certificate_file = open("pebble.minica.pem", "rb")
		pebble_certificate = pebble_certificate_file.read()
		pebble_certificate_file.close()			
		self.wfile.write(self.certificate)
		print(pebble_certificate + self.certificate)
		self.has_served_certificate = True
		print("Certificate request received and served.")
	
	def do_POST(self):
		self.send_response(200)
		self.send_header("Content-type", "application/pem-certificate-chain")
		self.end_headers()
		pebble_certificate_file = open("pebble.minica.pem", "rb")
		pebble_certificate = pebble_certificate_file.read()
		pebble_certificate_file.close()			
		self.wfile.write(self.certificate)
		print(pebble_certificate + self.certificate)
		self.has_served_certificate = True
		print("Certificate request received and served.")


