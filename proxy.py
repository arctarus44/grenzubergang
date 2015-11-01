#!/usr/bin/env python2

import cherryproxy
import base64
from BeautifulSoup import BeautifulSoup as bs

#################################### Utils #####################################
def decode_baseX(string):
	""" Decode a string converted into a base64/32/16 string."""
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



#################################### Filter ####################################

# Header
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
	"""For testing purpoise"""
	import random
	if random.randint(0, 100) < 50:
		print "we block"
		return True
	else:
		print "we do not block"
		return False


################################## The Proxy ###################################

class FilteringProxy(cherryproxy.CherryProxy):

	__filter_header = [filter_header_random]
	__filter_response = []
	__filter_request = []


	def filter_request_headers(self):
		headers = self.req.headers
		for f in self.__filter_header:
			if f(headers):
				self.set_response_forbidden(reason="I don't want to.")
				break



if __name__ == "__main__":

	proxy = FilteringProxy(address='localhost', port=8000,
	                       server_name='grenzubergang-Proxy',
	                       debug=True, log_level=0, options=None,
	                       parent_proxy=None)

	try:
		proxy.start()
	except KeyboardInterrupt:
		proxy.stop()
