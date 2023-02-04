from auxiliary import *
from commandline import *

import argparse #part of standard library
import requests
import dnslib
import socket #part of standard library

from base64 import urlsafe_b64encode, urlsafe_b64decode
import json
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import DSS

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import NoEncryption
#extract_domain_from_list = (lambda domain_list: domain_list[0])
#
#extract_1st_domain_from_list = (lambda list_of_list_domains: extract_domain_from_list(list_of_list_domains[0]))
#
#x509_DNSName_flattener = (lambda list_of_list_domains: [x509.DNSName(domain_list[0]) for domain_list in list_of_list_domains])
#rfc8555, page 22

#Note: All page and section indication are done for rfc8555, unless specified otherwise

class ACME_Client():
	
	def __init__(self, args, root_certificate, http_server_class, https_server_class, dns_resolver):
		self.args = args
		self.ACME_Server_dir_URL = args.dir
		self.root_certificate = root_certificate
		
		self.http_server_class = http_server_class
		self.https_server_class = https_server_class
		self.dns_resolver = dns_resolver
		
		#TO COMMENT IN
		#https://www.w3schools.com/python/ref_requests_get.asp
		#https://www.geeksforgeeks.org/ssl-certificate-verification-python-requests/
		#Need root certificate?
		#Note: ACME client - ACME server interaction is over HTTPS -> yes need it
		response = requests.get(url = self.ACME_Server_dir_URL, verify = self.root_certificate)
		#https://stackoverflow.com/questions/6386308/http-requests-and-json-parsing-in-python
		#response status code = 200, page 22
		if (debug):
			print("ACME Client: __init__")
			print(response) #<Response [200]>
			print(10 * "-")
#			print(response.headers)
#			print(10 * "-")
#			print(response.headers.get('content-type')) #application/json; charset=utf-8
#			print(10 * "-")
			print(response.json())
			
		if (debug):
			print(self.dns_resolver.hashmap)
			
		DICT_response_JSON_decoded = response.json()
		self.newNonce_address = DICT_response_JSON_decoded["newNonce"]
		self.newAccount_address = DICT_response_JSON_decoded["newAccount"]
		self.newOrder_address = DICT_response_JSON_decoded["newOrder"]
#		self.newAuthz_address = DICT_response_JSON_decoded["newAuthz"]
		self.revokeCert_address = DICT_response_JSON_decoded["revokeCert"]
		self.keyChange_address = DICT_response_JSON_decoded["keyChange"]
		self.meta = DICT_response_JSON_decoded["meta"]
		#meta contains TOS, website, caaId, ext. acc. requi (page 24)
				
		#_generate_keypair() #invoke when needed, maybe use existing ACME account
		self.private_key = None
		self.public_key = None
		
		self.anti_replay_nonce = None;
		
		#account creation
		self.account_URL = None
		self.kid = None
		
		#certificate issuance
		self.authorizations_list = None
		self.finalize_address = None
		self.current_authorization_address = None
				
		#challenges
		self.challenge_URL = None
		self.challenge_token = None
		
		#finalize
		self.RSA_key = None
		self.csr = None
		self.base64_encoded_csr_DER_format = None
		
		#download certificate
		self.certificate_download_URL = None
		self.certificate = None
		self.certificate_PEM = None
		self.certificate_DER = None
		
		#revoke certificate
		self.base64_encoded_certificate_DER_format = None
		
		#TO COMMENT IN
		if (debug):
			print("Init. ACME_Client instance.")
			print(20 * "-")
			print(self.ACME_Server_dir_URL)
			print(self.certificate)
			print(DICT_response_JSON_decoded)
			print(20 * "-")
	
	def get_nonce(self): #p22, and p34, 7.2
		#https://requests.readthedocs.io/en/latest/api/#requests.Response.status_code
		response = requests.head(url = self.newNonce_address, verify = self.root_certificate)
#		if (response.status_code == 200):
#			DICT_response_headers = response.headers;
#			self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
#		else:
#			print("Error in get_nonce: status_code not 200")
			
		DICT_response_headers = response.headers;
		self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
			
		if (debug):
			print("get_nonce:")
			print(20 * "-")
			print(response)
			print(response.headers)
			print("NONCE:", end="")
			print(self.anti_replay_nonce)
			print(20 * "-")
			#print(DICT_response_headers["Replay-Nonce"])
		#get request -> 204
		
	def _base64url_encode(self, obj, json_b): #move outside of class?
		if (debug):
			print("_base64url_encode:")
			print(20 * "-")
			print(obj)
			print(json_b)
			if json_b:
				print(urlsafe_b64encode(json.dumps(obj).encode(encoding = encoding_utf_8)).rstrip(b"=").decode(encoding = encoding_utf_8))
			else:
				print(urlsafe_b64encode(obj).rstrip(b"=").decode(encoding = encoding_utf_8))
			print(20 * "-")
				
		if json_b: #using json
			return urlsafe_b64encode(json.dumps(obj).encode(encoding = encoding_utf_8)).rstrip(b"=").decode(encoding = encoding_utf_8)
		else: #using bytes
			return urlsafe_b64encode(obj).rstrip(b"=").decode(encoding = encoding_utf_8)
	
	def _init_ECDSA(self):
		self.ECDSA_signer = DSS.new(self.private_key, "fips-186-3")
		self.ECDSA_verifier = DSS.new(self.public_key, "fips-186-3")
	
	def _generate_keypair(self):
		#https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html?highlight=ECC#ecc-table
		self.private_key = ECC.generate(curve = "NIST P-256")
		self.public_key = self.private_key.public_key()
#		self.private_key = DSA.generate(2048)
#		self.public_key = self.private_key.publickey()
		self._init_ECDSA()
		if (debug):
			print("_generate_keypair:")
			print(20 * "-")
			print(self.private_key)
			print(self.public_key)
			print(20 * "-")
		
	def _generate_jwk(self):
		#https://www.rfc-editor.org/rfc/rfc7517
		#https://ldapwiki.com/wiki/ES256
		#P-256 Elliptic Curve, and its x and y coordinates are the base64url-encoded values
		x_field_value = self._base64url_encode(self.public_key.pointQ.x.to_bytes(), False) #line 130
		y_field_value = self._base64url_encode(self.public_key.pointQ.y.to_bytes(), False)
		#That's the order used in the rfc document
		jwk_field = {
					"kty": "EC",
					"crv": "P-256",
					"x": x_field_value,
					"y": y_field_value
					}
		if (debug):
			print("_generate_jwk:")
			print(20 * "-")
			print(jwk_field)
			print(20 * "-")
			
		return jwk_field
	
	def _generate_protected_field(self, mode):
		if (mode == "Account creation"): #if true, then this is used for account creation
			jwk_field = self._generate_jwk() #ca line 160
			protected_field = {
								"alg": "ES256", 
								"jwk": jwk_field, 
								"nonce": self.anti_replay_nonce, 
								"url": self.newAccount_address
								}
			if (debug):
				print("_generate_protected_field:")
				print(20 * "-")
				print(mode)
#				print(protected_field)
#				print(json.dumps(protected_field))
#				print(json.dumps(protected_field).encode(encoding = encoding_utf_8))
#				print(urlsafe_b64encode(json.dumps(protected_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(protected_field, True))
				print("END _generate_protected_field")
				print(20 * "-")
			return self._base64url_encode(protected_field, True)
			
		elif (mode == "Certificate issuance request"):
			protected_field = {
								"alg": "ES256", 
								"kid": self.kid, 
								"nonce": self.anti_replay_nonce, 
								"url": self.newOrder_address
								}
			if (debug):
				print("_generate_protected_field:")
				print(20 * "-")
				print(mode)
				print(protected_field)
				print(json.dumps(protected_field))
				print(json.dumps(protected_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(protected_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(protected_field, True))
				print(20 * "-")
			return self._base64url_encode(protected_field, True)
			
		elif (mode == "Fetch challenge"):
			protected_field = {
								"alg": "ES256", 
								"kid": self.kid, 
								"nonce": self.anti_replay_nonce, 
								"url": self.current_authorization_address
								}
			if (debug):
				print("_generate_protected_field:")
				print(20 * "-")
				print(mode)
				print(protected_field)
				print(json.dumps(protected_field))
				print(json.dumps(protected_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(protected_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(protected_field, True))
				print(20 * "-")
			return self._base64url_encode(protected_field, True)
			
		elif (mode == "_respond_to_dns_challenge" or mode == "_respond_to_http_challenge"):
			protected_field = {
								"alg": "ES256", 
								"kid": self.kid, 
								"nonce": self.anti_replay_nonce, 
								"url": self.challenge_URL
								}
			if (debug):
				print("_generate_protected_field:")
				print(20 * "-")
				print(mode)
				print(protected_field)
				print(json.dumps(protected_field))
				print(json.dumps(protected_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(protected_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(protected_field, True))
				print(20 * "-")
			return self._base64url_encode(protected_field, True)
		
		elif (mode == "poll_4_status"):
			protected_field = {
								"alg": "ES256", 
								"kid": self.kid, 
								"nonce": self.anti_replay_nonce, 
								"url": self.current_authorization_address
								}
			if (debug):
				print("_generate_protected_field:")
				print(20 * "-")
				print(mode)
				print(protected_field)
				print(json.dumps(protected_field))
				print(json.dumps(protected_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(protected_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(protected_field, True))
				print(20 * "-")
			return self._base64url_encode(protected_field, True)
		
		elif (mode == "poll_4_status:poll_4_status"):
			protected_field = {
								"alg": "ES256", 
								"kid": self.kid, 
								"nonce": self.anti_replay_nonce, 
								"url": self.account_URL
								}
			if (debug):
				print("_generate_protected_field:")
				print(20 * "-")
				print(mode)
				print(protected_field)
				print(json.dumps(protected_field))
				print(json.dumps(protected_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(protected_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(protected_field, True))
				print(20 * "-")
			return self._base64url_encode(protected_field, True)
		
		elif (mode == "finalize_order"):
			protected_field = {
								"alg": "ES256", 
								"kid": self.kid, 
								"nonce": self.anti_replay_nonce, 
								"url": self.finalize_address
								}
			if (debug):
				print("_generate_protected_field:")
				print(20 * "-")
				print(mode)
				print(protected_field)
				print(json.dumps(protected_field))
				print(json.dumps(protected_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(protected_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(protected_field, True))
				print(20 * "-")
			return self._base64url_encode(protected_field, True)
		
		elif (mode == "download_certificate"):
			protected_field = {
								"alg": "ES256", 
								"kid": self.kid, 
								"nonce": self.anti_replay_nonce, 
								"url": self.certificate_download_URL
								}
			if (debug):
				print("_generate_protected_field:")
				print(20 * "-")
				print(mode)
				print(protected_field)
				print(json.dumps(protected_field))
				print(json.dumps(protected_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(protected_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(protected_field, True))
				print(20 * "-")
			return self._base64url_encode(protected_field, True)
			
		elif (mode == "certificate_revocation"):
			protected_field = {
								"alg": "ES256", 
								"kid": self.kid, 
								"nonce": self.anti_replay_nonce, 
								"url": self.revokeCert_address
								}
			if (debug):
				print("_generate_protected_field:")
				print(20 * "-")
				print(mode)
				print(protected_field)
				print(json.dumps(protected_field))
				print(json.dumps(protected_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(protected_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(protected_field, True))
				print(20 * "-")
			return self._base64url_encode(protected_field, True)
	
	def _generate_payload_field(self, mode): #p35
		if (mode == "Account creation"):
			payload_field = { 	
							"termsOfServiceAgreed": True,
							"contact": [
										"mailto:debug_mode@debug_mode.com",
										"mailto:admin@admin.com"
										]
							}
			if (debug):
				print("_generate_payload_field:")
				print(20 * "-")
				print(mode)
				print(payload_field)
#				print(json.dumps(payload_field))
#				print(json.dumps(payload_field).encode(encoding = encoding_utf_8))
#				print(urlsafe_b64encode(json.dumps(payload_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(payload_field, True))
				print(20 * "-")
			return self._base64url_encode(payload_field, True)
			
		elif (mode == "Certificate issuance request"):
			#page 45, 7.4
			identifiers = []
			for identifier in self.args.domain:
				identifier_dict = {  
									"type": "dns",
									"value": extract_domain_from_list(identifier) #args.domain is list of lists; identifier = [ele]; value = ele
									}
				identifiers.append(identifier_dict)
			payload_field = {
							"identifiers": identifiers
							} #notbefore/notAfter are optional
			if (debug):
				print("_generate_payload_field:")
				print(20 * "-")
				print(mode)
				print(payload_field)
				print(json.dumps(payload_field))
				print(json.dumps(payload_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(payload_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(payload_field, True))
				print(20 * "-")
			return self._base64url_encode(payload_field, True)
			
		elif (mode == "_respond_to_dns_challenge" or mode == "_respond_to_http_challenge"):
			#page 55, rfc8555, json body is empty
			payload_field = {}
			if (debug):
				print("_generate_payload_field:")
				print(20 * "-")
				print(mode)
				print(payload_field)
				print(json.dumps(payload_field))
				print(json.dumps(payload_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(payload_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(payload_field, True))
				print(20 * "-")
			return self._base64url_encode(payload_field, True)
		
		elif (mode == "Fetch challenge" or mode == "poll_4_status" or mode == "poll_4_status:poll_4_status" or mode == "download_certificate"):
			#page 57, it's not empty json but just "", not even base64-url encoded
			payload_field = ""
			if (debug):
				print("_generate_payload_field:")
				print(20 * "-")
				print(mode)
				print(payload_field)
				print(20 * "-")
			return payload_field
		
		elif (mode == "finalize_order"):
			payload_field = { 	
							"csr": self.base64_encoded_csr_DER_format
							}
			if (debug):
				print("_generate_payload_field:")
				print(20 * "-")
				print(mode)
				print(payload_field)
				print(json.dumps(payload_field))
				print(json.dumps(payload_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(payload_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(payload_field, True))
				print(20 * "-")
			return self._base64url_encode(payload_field, True)
		
		elif (mode == "certificate_revocation"):
			payload_field = { 	
							"certificate": self.base64_encoded_certificate_DER_format,
							"reason": 4
							}
			if (debug):
				print("_generate_payload_field:")
				print(20 * "-")
				print(mode)
				print(payload_field)
				print(json.dumps(payload_field))
				print(json.dumps(payload_field).encode(encoding = encoding_utf_8))
				print(urlsafe_b64encode(json.dumps(payload_field).encode(encoding = encoding_utf_8)))
				print(self._base64url_encode(payload_field, True))
				print(20 * "-")
			return self._base64url_encode(payload_field, True)
			
		
	def _generate_signature_field(self, base64url_protected, base64url_payload):
		#https://datatracker.ietf.org/doc/html/rfc7515#section-5.1
		#https://datatracker.ietf.org/doc/html/rfc7515#section-7.2
		#https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3 -> where is hash?
		#https://www.scottbrady91.com/jose/jwts-which-signing-algorithm-should-i-use
		##https://www.rfc-editor.org/rfc/rfc7518#section-3.4 -> hash then sign
		#template of request to send on page 35
		#TODO POTENTIAL SOURCE OF BUG
		#According to: https://pycryptodome.readthedocs.io/en/latest/src/public_key/dsa.html#Crypto.PublicKey.DSA.DsaKey
		#this works
#		print("pyaload: ", end="")
#		print(base64url_payload)
		hash_value = SHA256.new((base64url_protected + "." + base64url_payload).encode(encoding = encoding_utf_8)) #encode to convert it to bytes
		
		signature = self.ECDSA_signer.sign(hash_value) #type: byte
		if (debug): 
			print("_generate_signature_field:")
			print(20 * "-")
			print(base64url_protected)
			print(10 * "-")
			print(base64url_payload)
			print(10 * "-")
			print(hash_value)
			print(10 * "-")
			print(signature)
			print(20 * "-")
			
		return self._base64url_encode(signature, False)
		
	def _generate_body(self, mode):
		if (debug):
			print("INIT GENERATE PROTECTED FIELD:")
		protected_field = self._generate_protected_field(mode); #ca 178
		if (debug):
			print("INIT GENERATE PAYLOAD FIELD")
		payload_field = self._generate_payload_field(mode); #ca. 333
		#signature_field = self._generate_signature_field(protected_field, payload_field); #ca 426
		if (debug):
			print("INIT GENERATE SIGNATURE AND BODY")
		body = { 	
				"protected": protected_field,
				"payload": payload_field,
				"signature": self._generate_signature_field(protected_field, payload_field)
				}
		if (debug):
			print("_generate_body:")
			print(20 * "-")
			print(body)
			print(20 * "-")
		return body
	
	def create_account(self): #p34, 7.3
		#page 8, step 0
		#need to generate es256 keypair
		#must use json over https (page 7, section 4)
		#https://ldapwiki.com/wiki/ES256
		if (self.anti_replay_nonce is None):
			self.get_nonce() #ca. line 114 
#		if (debug):
#			print("NONCE: ")
#			print(self.anti_replay_nonce)
		#https://stackoverflow.com/questions/3302946/how-to-decode-base64-url-in-python
		#https://lindevs.com/code-snippets/base64url-encode-and-decode-using-python
		#1. generate private/public key pair
		if (debug):
			print("create_account: generate keypair and generate body")
		self._generate_keypair() #ca. line 150
		body = self._generate_body("Account creation") #ca line 433
		#https://www.w3schools.com/python/ref_requests_post.asp
		#Header from page 35, rfc8555
		header = {
					"Content-Type": "application/jose+json"
					}
		
		if (debug):
			print("create_account TO SEND:")
			print(header)
			print(body)
		
		response = requests.post(url = self.newAccount_address, headers = header, json = body, verify = self.root_certificate)
		#page 14, rfc8555, after post request, have new nonce
		#page 22, status code should be 201
		#page 36, status code should be 200 if already registered account using same key
		DICT_response_headers = response.headers;
		self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
		
		self.kid = DICT_response_headers["Location"]
		#11:40 30 oct
#		self.account_URL = DICT_response_headers["Location"]
#		self.kid = self.account_URL
		
		
		if (debug):
			print("create_account:")
			print(20 * "-")
			print(response)
			print(response.headers)
			print(self.kid)
			print(20 * "-")

	def submit_order(self):
		#page 8, step 1
		#rfc 8555, 7.4, page 44 - 49
		body = self._generate_body("Certificate issuance request") #ca line 433
		header = {
					"Content-Type": "application/jose+json"
					}
		response = requests.post(url = self.newOrder_address, headers = header, json = body, verify = self.root_certificate)
		DICT_response_headers = response.headers; #status code 201
		self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
		response_JSON = response.json()
		self.authorizations_list = response_JSON["authorizations"]
		self.finalize_address = response_JSON["finalize"]
		if (debug):
			print("submit_order:")
			print(20 * "-") 
			print(response)
			print(response_JSON)
			print(20 * "-")

	def _generate_thumbprint(self):
		#https://www.rfc-editor.org/rfc/rfc7638
		#JWK Thumbprint The digest value for a JWK.
		jwk_field = self._generate_jwk() #line 160
		#https://www.rfc-editor.org/rfc/rfc7638#section-3.2 -> different order than in https://www.rfc-editor.org/rfc/rfc7517
		jwk_field = dict(sorted(jwk_field.items())) #reorder by keys
		
		#no spaces (as in example of rfc 7638), convert dict -> str -> binary string (under utf8)
		#TODO: POTENTIAL BUG HERE
		hash_value = SHA256.new("".join(json.dumps(jwk_field).split()).encode(encoding = encoding_utf_8)).digest()
		if (debug):
			print("_generate_thumbprint:")
			print(20 * "-")
			print(jwk_field)
			print(hash_value)
			print(self._base64url_encode(hash_value, False))
			print(20 * "-")
		return self._base64url_encode(hash_value, False)
		
	def _generate_key_authorization(self):
		#rfc 8555, page 62, section 8.1
		return self.challenge_token + "." + self._generate_thumbprint()

	def _respond_to_dns_challenge(self, DICT_challenge):
		#page 66-67, section 8.4
		key_authorization = self._generate_key_authorization() #509
		#TODO: POTENTIAL BUGHERE
		hash_value = SHA256.new(key_authorization.encode()).digest()
		#key_auth_hashval = self._base64url_encode(hash_value, False)
		#page 46: 2 identifiers;
		#page 67: use the first identifier
		#page 46: also states: no assumption on order of identifiers or authorizations
		#domain = extract_1st_domain_from_list(self.args.domain)
						
		
		#TODO
#		for ele in DNSName_flattener(self.args.domain):
			
		#there is at least one identifier -> save to go for first identifier in the list
		dns_value = "_acme-challenge." + extract_1st_domain_from_list(self.args.domain) + ". 300 TXT " + self._base64url_encode(hash_value, False)
		
		#TODO
		#TODO DNS reprogramming
		
		if (debug):
			print("_respond_to_dns_challenge: ")
			print(key_authorization)
			print(10 * "-")
			print(hash_value)
			print(10 * "-")
			print(dns_value)
			print(10 * "-")
			
		resolver = self.dns_resolver
		
		if (debug):
			print("PRINTING OUT HASHMAP")
			print(resolver.hashmap)
		
		for identifier in self.args.domain: #go through each element in domain list
			resolver.set_dns_challenge_response(extract_domain_from_list(identifier), dns_value)
			resolver.set_dns_challenge_response("_acme-challenge." + extract_domain_from_list(identifier), dns_value)
						
#			resolver.set_dns_challenge_response("_acme-challenge." + extract_domain_from_list(identifier), "_acme-challenge." + extract_domain_from_list(identifier) + ". 300 IN TXT " + self._base64url_encode(hash_value, False)) #new expimental
		
		if (debug):
			print("PRINTING OUT HASHMAP")
			print(resolver.hashmap)
			
		#self.self.dns_resolver.set_dns_challenge_response(extract_1st_domain_from_list(self.args.domain), dns_value)
		#self.dns_server._set_dns_value(dns_value)
		
		#time.sleep(3.14) #small delay to have the server reconfigured s.t. by the time acme server tests validity, it should go fairly fast
		
		#page 67: HTTP server is ready
		#https://stackoverflow.com/questions/10114224/how-to-properly-send-http-response-with-python-using-socket-library-only
		body = self._generate_body("_respond_to_dns_challenge")
		header = {
					"Content-Type": "application/jose+json"
					}
		response = requests.post(url = self.challenge_URL, headers = header, json = body, verify = self.root_certificate)
		DICT_response_headers = response.headers; #status code 201
		self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
		if (debug):
			print("_respond_to_dns_challenge:")
			print(20 * "-")
			print(response)
			print(response.headers)
			print(20 * "-")
				
	def _respond_to_http_challenge(self, DICT_challenge):
		key_authorization = self._generate_key_authorization() #508
		#set http server with this value
#		print(20 * "*")
#		print(20 * "*")
#		print("_respond_to_http_challenge")
#		print(20 * "*")
#		print(20 * "*")
		
#		print(20 * "*")	
#		print("key_authorization computed")
#		print(key_authorization)
#		print(20 * "*")
		
		#TODO
		self.http_server_class.key_authorization = key_authorization
		#self.http_server._set_key_authorization(key_authorization)
		if (debug):
			print("_respond_to_http_challenge")
			print(self.http_server_class.key_authorization)
		
#		print(20 * "*")	
#		print("key_authorization computed")
#		print(key_authorization)
#		print(20 * "*")

		#from section 8.3, specific string = key_authorization (in ASCII)
		#time.sleep(3.14) #small delay to have the server reconfigured s.t. by the time acme server tests validity, it should go fairly fast
		
		#page 64: HTTP server is ready
		#https://stackoverflow.com/questions/10114224/how-to-properly-send-http-response-with-python-using-socket-library-only
		body = self._generate_body("_respond_to_http_challenge") #433
		header = {
					"Content-Type": "application/jose+json"
					}
		response = requests.post(url = self.challenge_URL, headers = header, json = body, verify = self.root_certificate)
		DICT_response_headers = response.headers; #status code 201
		self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
		
#		print(20 * "*")
#		print(20 * "*")
#		print("MARKING HERE: _respond_to_http_challenge:")
#		print(20 * "-")
#		print(self.http_server_class.key_authorization)
#		print(20 * "-")
#		print(response)
#		print(DICT_response_headers)
#		print(20 * "-")
#		print(20 * "*")
#		print("MARKING HERE: ENDED _respond_to_http_challenge:")
#		print(20 * "*")
		
		if (debug):
			print("_respond_to_http_challenge:")
			print(20 * "-")
			print(response)
			print(DICT_response_headers)
			print(20 * "-")
			
	def poll_4_status(self, mode):
		#page 56-57, rfc8555
		#self.current_authorization_address contains current authorization address
		#page 24, 7.1.2, status
		#page 31, overview
		
		response = None
		body = None
		header = {
					"Content-Type": "application/jose+json"
					}
		while True:
			if (mode == "respond_to_challenges"):
				body = self._generate_body("poll_4_status")
				response = requests.post(url = self.current_authorization_address, headers = header, json = body, verify = self.root_certificate)
			elif (mode == "await_download_certificate"):
				body = self._generate_body("poll_4_status:poll_4_status")
				response = requests.post(url = self.account_URL, headers = header, json = body, verify = self.root_certificate)
			else:
				print("poll_4_status: ERROR - unknown mode")
				break
				
			time.sleep(5) #5-10 seconds, page 63 suboptimal position
			DICT_response_headers = response.headers; #status code 201
			self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
			response_JSON = response.json()
			
#			print(self.dns_resolver.hashmap)
			
			if (debug):
				print("poll_4_status: ", end="")
				print(response)
				print(DICT_response_headers)
				print(response_JSON)
#				print(self.dns_resolver.hashmap)
				
			authorization_object_state = response_JSON["status"]
#			if (authorization_object_state == "processing"):
#				continue #page 61, page63
			if (authorization_object_state == "valid"):
				print("poll_4_status: SUCCESS - status = VALID")
				if (debug):
					print("poll_4_status: ", end="")
					print(response)
					print(DICT_response_headers)
					print(response_JSON)
				return response
			elif (authorization_object_state == "invalid"):
				print("poll_4_status: ERROR - status = invalid")
				if (debug):
					print(response)
					print(DICT_response_headers)
					print(response_JSON)
	#				print(self.dns_resolver.hashmap)
				return response
				#TODO: Figure out what to do here.
			time.sleep(5) #5-10 seconds, page 63, better, can now process response, and if pending, just wait
				
			
	def respond_to_challenges(self, challenges_list):
		#"dns01", "http01" (from command line argument)
		#rfc8555, page 54, 7.5.1
		#section 8, rfc8555, page 60
		for DICT_challenge in challenges_list: #can be both dns and http, filter it out
			if (debug):
				print("respond_to_challenges: ", end="")
				print(DICT_challenge)
				
			challenge_type = DICT_challenge["type"]
			self.challenge_URL = DICT_challenge["url"]
			self.challenge_token = DICT_challenge["token"]
			
			#the challenge type is given as command line argument
			#according to its description, it either matches what the server sends
			#or we ignore the type the server sends.
			if (self.args.challenge_type[0] == "dns01" and challenge_type == "dns-01"): 
				if (debug):
					print("respond_to_challenges: DNS challenge")
				self._respond_to_dns_challenge(DICT_challenge) #513
				if (debug):
					print("respond_to_challenges: DNS WAIT")
				authorization_object_state = self.poll_4_status("respond_to_challenges") #line 574
				if (debug):
					print("respond_to_challenges: DNS DONE")
				
			elif (self.args.challenge_type[0] == "http01" and challenge_type == "http-01"):
#				if (debug):
#				print(20 * "C")
#				print("respond_to_challenges: http challenge")
				self._respond_to_http_challenge(DICT_challenge) #line 548
#				if (debug):
#				print("respond_to_challenges: http WAIT")
#				print(20 * "C")
				authorization_object_state = self.poll_4_status("respond_to_challenges")
#				if (debug):
#				print(20 * "P")
#				print("respond_to_challenges: http DONE")
#				print(authorization_object_state)
#				print(20 * "P")
				
			else:
				if (debug):
					print("respond_to_challenges: ERROR - unknown challenge type combination: ")
					print(challenge_type)
					print(self.args.challenge_type)
				#break
#			authorization_object_state = self.poll_4_status("respond_to_challenges")
#			break #found matching challenging type
						
	def process_authorizations_list(self): #get challenge per authorization_address
		#page 8, step 2
		#page 46, rfc8555, states that all authorization referenced must be completed
		#page 53, 75.
		#page 54, response (should be 200)
		#page 13, 6.3: post-as-get: get with empty payload field
		i = 0
		for authorization_address in self.authorizations_list:
			#fetch challenge from authorization_address
			self.current_authorization_address = authorization_address
			body = self._generate_body("Fetch challenge") #line ca 433
			header = {
						"Content-Type": "application/jose+json"
						}
			response = requests.post(url = self.current_authorization_address, headers = header, json = body, verify = self.root_certificate)
			DICT_response_headers = response.headers; #status code 201
						
			self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
			response_JSON = response.json()
			
			if (debug):
				print("process_authorizations_list for: ", end="")
				print(authorization_address)
				print(10 * "-")
				print(response)
				print(10 * "-")
				print(response.headers)
				print(10 * "-")
				print(response_JSON)
				print(10 * "-")
#				return
			
#			return
			challenges_list = response_JSON["challenges"]
			
			#respond to challenge (page 54,section 7.5.1)
			self.respond_to_challenges(challenges_list) #line 613
			if (debug):
				print("Iteration done: " + str(i))
				i += 1 #tracking id
#			return
	
	def finalize_order(self):
		#page 8, step 3
		#page 47
		#https://www.rfc-editor.org/rfc/rfc2986
		'''
		A certification request consists of a distinguished name, a public key,
		and optionally a set of attributes, collectively signed by the entity
		requesting certification. 
		'''
		#return from ACME server: X.509 public key certificate
		'''
		 A certification request consists of three parts: "certification
			request information," a signature algorithm identifier, and a digital
			signature on the certification request information.  The
			certification request information consists of the entity's
			distinguished name, the entity's public key, and a set of attributes
			providing other information about the entity.
		'''
		#Googling python csr encoding leads to https://cryptography.io/en/latest/x509/reference/
		#https://cryptography.io/en/latest/x509/tutorial/#
		self.RSA_key = rsa.generate_private_key(
												public_exponent=65537,
												key_size=2048
												)	
		self.csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
			# Provide various details about who we are.
			x509.NameAttribute(NameOID.COUNTRY_NAME, u"CA"),
			x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Province of ACME"),
			x509.NameAttribute(NameOID.LOCALITY_NAME, u"ACME"),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ACME Cooperate"),
			x509.NameAttribute(NameOID.COMMON_NAME, extract_1st_domain_from_list(self.args.domain)), #just take one domain
		])).add_extension(
			x509.SubjectAlternativeName(
				x509_DNSName_flattener(self.args.domain)), #observe this one adds the domain above as well
			critical=False,	
		# Sign the CSR with our private key.
		).sign(self.RSA_key, hashes.SHA256())
		#page 47: csr is sent in the base64url-encoded version of the DER format
		#https://cryptography.io/en/latest/x509/reference/#x-509-csr-certificate-signing-request-object -> public bytes, go to sources
		#https://github.com/pyca/cryptography/blob/main/src/cryptography/x509/base.py#L481-L485
		#request encoding to DER format
		csr_DER_format = self.csr.public_bytes(Encoding.DER)
		self.base64_encoded_csr_DER_format = self._base64url_encode(csr_DER_format, False)
		body = self._generate_body("finalize_order")
		header = {
					"Content-Type": "application/jose+json"
					}
		response = requests.post(url = self.finalize_address, headers = header, json = body, verify = self.root_certificate)
		DICT_response_headers = response.headers; #status code 201
		self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
		
		if (debug):
			print("finalized")
			print(20 * "-")
			print(response)
			print(DICT_response_headers)
			print(20 * "-")
		#polling
#		print("FINALIZED: ", end="")
#		print(self.finalize_address)
#		print(20 * "-")
#		print(response)
#		print(10 * "-")
#		print(DICT_response_headers)
#		print(10 * "-")
#		print(response.json())
#		print(20 * "-")
#		print(self.account_URL)
#		print(self.kid)
#		print("TERMINATE finalize_order")
		
		#page 37 and page 49: have different location field values
		#page 37, location value used as kid
		self.account_URL = DICT_response_headers["Location"]
#		print(self.account_URL)
			
	def download_certificate(self):
		#page 8, step 4
		#page 51-52, section 7.4.2, rc8555
		
		#await isuance
		#TODO to debug
		#wait according to page 48
#		response_JSON = response.json()
#		status = response_JSON["status"]
#		if (status != "valid"):
#			response = self.poll_4_status("await_download_certificate")
#		print(20 * "*")
#		print("INIT download_certificate")
		response = self.poll_4_status("await_download_certificate")
		if (debug):
			print("finalize_order: ", end="")
			print(response)
			print("finalize_order: terminate")
		response_JSON = response.json()
		
#		print("download_certificate")
#		print(response)
#		print(response.headers)
#		print(response_JSON)
		
		self.certificate_download_URL = response_JSON["certificate"]
		
		#onto downloading certificate
		
		#https://stackoverflow.com/questions/56150612/is-accept-header-needed-for-a-post-method-which-doesnt-return-any-content-to-cl
		body = self._generate_body("download_certificate")
		#certificate is PEM encoded
		header = {
					"Content-Type": "application/jose+json",
					"Accept": "application/pem-certificate-chain"
					}
		response = requests.post(url = self.certificate_download_URL, headers = header, json = body, verify = self.root_certificate)
		DICT_response_headers = response.headers; #status code 201
		self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
		self.certificate = response.content #bytes
		
		
		#https://cryptography.io/en/latest/x509/reference/#cryptography.x509.load_pem_x509_certificate
		#Deserialize a certificate from PEM encoded data. PEM certificates are base64 decoded
		#TODO: POTENTIAL BUG HERE
		
		self.certificate_PEM = self.certificate
		self.https_server_class.certificate = self.certificate_PEM
		#self.https_server_class.certificate = self.certificate
		
		self.certificate_DER = x509.load_pem_x509_certificate(self.certificate).public_bytes(Encoding.DER) #convert it into pem format, bytes
		
		#self.certificate_PEM = x509.load_pem_x509_certificate(self.certificate)
#		self.certificate_PEM = self.certificate_PEM.public_bytes(Encoding.PEM) #convert into pem format, bytes

		if (debug):
			print("download_certificate:")
			print(20 * "-")
			print(response)
			print(response.headers)
			print(self.certificate)
			print(self.certificate_PEM)
			print(20 * "-")
			
#		print("CERTIFICATES")
#		print(20 * "*")	
#		print(20 * "-")
#		print(self.certificate_PEM)
#		print(20 * "-")
#		print(self.certificate_DER)
#		print(20 * "-")
#		print(20 * "*")	
#		print(self.certificate)
#		print(20 * "-")
#		print(20 * "*")	
		
	def certificate_revocation(self):
		#status code 200
		#7.6, page 58,59
		#use account key pair (easiser)
		#from above
#		certificate_DER_format = self.certificate_PEM.public_bytes(Encoding.DER)
		
#		print("START certificate_revocation:")
#		print(10 * "*")
#		#print(self.certificate[30:)
#		print(10 * "*")
#		print(self.certificate_PEM[28:-27])
#		print(10 * "*")
		
		self.base64_encoded_certificate_DER_format = self._base64url_encode(self.certificate_DER, False)
		
		body = self._generate_body("certificate_revocation")
		header = {
					"Content-Type": "application/jose+json",
					}
		response = requests.post(url = self.revokeCert_address, headers = header, json = body, verify = self.root_certificate)
		DICT_response_headers = response.headers; #status code 200
		self.anti_replay_nonce = DICT_response_headers["Replay-Nonce"]
		
		if (debug):
			print("certificate_revocation:")
			print(20 * "-")
			print(response)
			print(response.headers)
			print(20 * "-")
#		print("certificate_revocation:")
#		print(20 * "-")
#		print(response)
#		print(response.headers)
##		print(response.json())
#		print(20 * "-")
#		print("END certificate_revocation")
		
		
	def store_certificate_to_file(self):
		if (debug):
			print("store_certificate_to_file")
		file_certificate = open("certificate.pem", "wb")
		file_certificate.write(self.certificate_PEM)
		file_certificate.close()
	
	def store_key_to_file(self):
		if (debug):
			print("store_key_to_file")
		#from https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#serialization-formats
		#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization
		encryption = (PrivateFormat.OpenSSH.encryption_builder().kdf_rounds(30).build(b"Poorly chosen password"))
		
		file_key = open("keyfile.pem", "wb")
		file_key.write(self.RSA_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))  
#		print("store_key_to_file")
#		print(self.RSA_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
		file_key.close()
		
	def store_certificate_and_key_to_file(self):
		if (debug):
			print("store_certificate_and_key_to_file")
		self.store_certificate_to_file()
		self.store_key_to_file()