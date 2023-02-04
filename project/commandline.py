import argparse

'''
#### 3.3.2 | Command-line arguments <a name="arguments"></a>

Your application should support the following command-line arguments (passed to the `run` file):

**Positional arguments:**

- `Challenge type`
	_(required, `{dns01 | http01}`)_ indicates which ACME challenge type the client should perform. Valid options are `dns01` and `http01` for the `dns-01` and `http-01` challenges, respectively.

**Keyword arguments:**

- `--dir DIR_URL`
	_(required)_ `DIR_URL` is the directory URL of the ACME server that should be used.
- `--record IPv4_ADDRESS` 
	_(required)_ `IPv4_ADDRESS` is the IPv4 address which must be returned by your DNS server for all A-record queries. 
- `--domain DOMAIN`
	_(required, multiple)_ `DOMAIN`  is the domain for  which to request the certificate. If multiple `--domain` flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., `*.example.net`.
- `--revoke`
	_(optional)_ If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.
	
**Example:**
Consider the following invocation of `run`:

```
run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain netsec.ethz.ch --domain syssec.ethz.ch
```

When invoked like this, your application should obtain a single certificate valid for both `netsec.ethz.ch` and `syssec.ethz.ch`. It should use the ACME server at the URL `https://example.com/dir` and perform the `dns-01` challenge. The DNS server of the application should respond with `1.2.3.4` to all requests for `A` records. Once the certificate has been obtained, your application should start its certificate HTTPS server and install the obtained certificate in this server.

'''
#https://docs.python.org/3/howto/argparse.html#id1
#https://docs.python.org/3/library/argparse.html#argparse.ArgumentParser.add_argument
#https://docs.python.org/3/library/argparse.html#dest
#https://docs.python.org/3/howto/argparse.html#introducing-optional-arguments

#main calls this method via python main.py

def get_command_line_commands():
	parser = argparse.ArgumentParser()
	
	#add pos. arguments
	#Challenge type; returns challenge_type = [choice]
	parser.add_argument("challenge_type", nargs = 1, choices = ["dns01", "http01"], help = "Challenge type: _(required, `{dns01 | http01}`)_ indicates which ACME challenge type the client should perform. Valid options are `dns01` and `http01` for the `dns-01` and `http-01` challenges, respectively.", type = str)
	
	#add optional arguments
	#--dir DIR_URL
	parser.add_argument("--dir", help ="_(required)_ `DIR_URL` is the directory URL of the ACME server that should be used.", type = str)
	
	#--record IPv4_ADDRESS
	parser.add_argument("--record", nargs = 1, help = "_(required)_ `IPv4_ADDRESS` is the IPv4 address which must be returned by your DNS server for all A-record queries.", type = str)
	
	#--domain DOMAIN
	#MULTIPLE, cannot use nargs=* (implies that 0 args are okay)
	#--domain AAA --domain BBB => [AAA, BBB], use https://docs.python.org/dev/library/argparse.html#action
	parser.add_argument("--domain", nargs = 1, action = "append", help = "_(required, multiple)_ `DOMAIN`  is the domain for  which to request the certificate. If multiple `--domain` flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., `*.example.net`.", type = str)
	
	#--revoke
	#ValueError: nargs for store actions must be != 0; if you have nothing to store, actions such as store true or store const may be more appropriate
	#Gives desires result of setting revoke true/false depending if present
	parser.add_argument("--revoke", action ="store_true", help = "_(optional)_ If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.")
	
	#print out everything
#	parser.add_argument("--debug", action ="store_true", help = "If present, enter debug mode.")
	
	
	return parser
	