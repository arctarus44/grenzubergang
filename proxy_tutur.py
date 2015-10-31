#!/usr/bin/env python2

import cherryproxy
import base64
from BeautifulSoup import BeautifulSoup as bs


def decode_baseX(string):
	try:
		return base64.b64decode(string)
	except TypeError:
		pass
	try:
		return base64.b32decode(string)
	except TypeError:
		pass
	try:
		return base64.b16decode(string)
	except TypeError:
		pass
	raise TypeError("This is not base64/32/16 encoded string")

def filter_header_user_agent(headers):
	# ask : can we ust use a withlist rather than a black list ?
	"""Return true if the request or response need to be filtered"""
	agents = ["BinGet", "curl", "Java", "libwww-perl", "Microsoft URL Control",
	          "Peach", "PHP", "pxyscand", "PycURL", "Python-urllib", "Wget"]
	try:
		user_agent = headers["user-agent"]
		print user_agent
	except KeyError:
		return True
	else:
		for agent in agents:
			if agent in user_agent:
				return True
	return False

def filter_header_random(headers):
	import random
	if random.randint(0, 100) < 50:
		print "we block"
		return True
	else:
		print "we do not block"
		return False

class FilteringProxy(cherryproxy.CherryProxy):

	__filter_header = [filter_header_user_agent, filter_header_random]

	# uncomment if you want to see the specific part of the request.
	# def filter_request(self):
	# 	print("**** Request Header ****")
	# 	headers = self.req.headers
	# 	for key in headers.keys():
	# 		print(key + " -> " + headers[key])

	# 	print("\n**** HTTP method ****")
	# 	print("HTTP method -> "  + self.req.method)

	# 	print("\n**** scheme ****")
	# 	print("Scheme -> "  + self.req.scheme)

	# 	print("\n**** Client info ****")
	# 	print("Client info -> "  + self.req.netloc)

	# 	print("\n**** Requested path ****")
	# 	print("Path -> "  + self.req.path)

	# 	print("\n**** Requested path ****")
	# 	print("Query -> "  + self.req.query)


	def filter_request_headers(self):
		headers = self.req.headers
		for f in self.__filter_header:
			if f(headers): # if the filter says we need to block this request
				self.set_response_forbidden(reason="I don't want to.")
				break

	# def filter_response(self):
	# 	# call set_response if the response need to be blocked
	# 	pass



if __name__ == "__main__":

	proxy = FilteringProxy(address='localhost', port=8000,
	                       server_name='grenzubergang-Proxy',
	                       debug=True, log_level=0, options=None,
	                       parent_proxy=None)

	try:
		proxy.start()
	except KeyboardInterrupt:
		proxy.stop()
