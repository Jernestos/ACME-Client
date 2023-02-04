from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

#This file contains constants and small helper functions that don't fit in other files

encoding_utf_8 = "UTF-8"

extract_domain_from_list = (lambda domain_list: domain_list[0])

extract_1st_domain_from_list = (lambda list_of_list_domains: extract_domain_from_list(list_of_list_domains[0]))

x509_DNSName_flattener = (lambda list_of_list_domains: [x509.DNSName(domain_list[0]) for domain_list in list_of_list_domains])

DNSName_flattener = (lambda list_of_list_domains: [domain_list[0] for domain_list in list_of_list_domains])

#IP_Address = "127.0.0.1" #testing
IP_Address = "0.0.0.0" #eval

DNS_PORT = 10053
Challenge_HTTP_PORT = 5002 #all http01 challenges
Certificate_HTTPS_PORT = 5001 #TCP
Shutdown_HTTP_PORT = 5003

debug = False