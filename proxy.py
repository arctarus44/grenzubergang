#!/usr/bin/env python2

import cherryproxy
import base64
from BeautifulSoup import BeautifulSoup
import threading as thread
import logging
from ast import literal_eval

INLINE = ["span", "b", "big", "i", "small", "tt", "abbr", "acronym", "cite",
          "code", "dfn", "em", "kbd", "strong", "samp", "var", "a",
          "img", "map", "object", "q", "script", "sub", "sup", "label"]


#################################### Utils #####################################
def decode_baseX(string):
	""" Decode a string converted into a base64/32/16 string."""
	try:
		return base64.b64decode(string)
	except TypeError:
		pass
	try:
		return base64.urlsafe_b64decode(string)
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
	# raise TypeError("This is not base64/32/16 encoded string")


def decode_string(string):
	""" Test if a string contains the keyword 'SSH' """
	if 'ssh' in string or 'SSH' in string:
		return True
	return False


def extract_payload(html):
	"""Extract a payload from an html page."""

	def inline_gen(html):
		parser = BeautifulSoup(html, 'html.parser')
		for element in INLINE:
			elements = parser.findAll(element)
			inline = ""
			for tag in elements:
				inline += elt.next
			yield inline


	for payload in inline_gen(html):
		if decode_baseX(paylaod) != None:
			return payload
	return None



def extract_baseX(string, base=64):
	# todo base16
	nope64 = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
	          '\x08', '\t', '\n', '\x0b', '\x0c', '\r', '\x0e', '\x0f', '\x10',
	          '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18',
	          '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', ' ', '!',
	          '"', '#', '$', '%', '&', "'", '(', ')', '*', ',', '-', '.', '/',
	          ':', ';', '<', '>', '?', '@', '[', '\\', ']', '^', '_', '`',
	          '{', '|', '}', '~']

	nope32 = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
	          '\x08', '\t', '\n', '\x0b', '\x0c', '\r', '\x0e', '\x0f', '\x10',
	          '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18',
	          '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', ' ', '!',
	          '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.',
	          '/', '0', '1', '8', '9', ':', ';', '<', '>', '?', '@', 'N', '[',
	          '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
	          'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
	          'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~']

	if base == 64:
		nope = nope64
	elif base == 32:
		nope = nope32
	else:
		raise ValueError("Only the 64 and 32 base are accepted.")

	for char in nope:
		if char in string:
			string = string.replace(char, "")
	return string


#################################### Filter ####################################

# Header
def filter_header_user_agent(proxy):
	# ask : can we ust use a withlist rather than a black list ?
	"""Return true if the request or response need to be filtered"""
	agents = ["BinGet", "curl", "Java", "libwww-perl", "Microsoft URL Control",
	          "Peach", "PHP", "pxyscand", "PycURL", "Python-urllib", "Wget"]
	try:
		user_agent = proxy.req.headers["user-agent"]
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
	if random.randint(0, 100) < 20:
		print "we block"
		return True
	else:
		print "we do not block"
		return False

# Request
def filter_request_ssh(proxy):
	logging.debug("Searching a string ssh...")
	def has_ssh(data):
		""" Search the string "SSH" in the data, then return True or False."""
		try:
			if 'SSH' in decode_baseX(data):
				return True
			else:
				return False
		except TypeError:
			logging.debug("%s is not a baseX string.")
			return False
		except Exception as e:
			logging.error(e)
			return False

	def has_ssh_list(data, reverse=False):
		""" Sort the key and check if the ssh string is present. If reverse
		equal True, the keys are sort in decroissant order."""
		keys.sort(reverse=reverse)
		payload = ""
		for k in keys:
			paylaod += proxy.req.data[k]

		return has_ssh(payload)

	if "GET" in proxy.req.method:
		payload = proxy.req.url[1:]
		logging.debug("Payload = %s", payload)
		if has_ssh(payload):
			logging.debug("Blocking the request %s.", proxy.req.full_url)
			return True
		return False

	elif "POST" in proxy.req.method:
		logging.debug("Data received : %s.", proxy.req.data)
		try:
			data = literal_eval(proxy.req.data)
		except SyntaxError: # If it's not a JSON
			if has_ssh(proxy.req.data): # it's a string
				logging.debug("Blocking the request %s with the following payload %s.",
				              proxy.req.full_url, proxy.req.data)
				return True
			return True

		keys = data.keys()

		if len(keys) == 1:
			return has_ssh(data[keys[0]])
		else: # More than 1 key. We must sort the key
			if has_ssh_list(data):
				logging.debug("Blocking the request %s with the following payload %s.",
				              proxy.req.full_url, proxy.req.data)
				return True
			else: # Let's try the reverse sort
				if has_ssh_list(data, reverse=True):
					logging.debug("Blocking the request %s with the following reverse payload %s.",
				              proxy.req.full_url, proxy.req.data)
					return True
				return False


################################## The Proxy ###################################

class FilteringProxy(cherryproxy.CherryProxy):

	__filter_header = []
	__filter_response = []
	__filter_request = [filter_request_ssh]

	def filter_request_headers(self):
		logging.debug("Filtering the headers.")
		headers = self.req.headers
		for f in self.__filter_header:
			if f(self):
				self.set_response_forbidden(reason="I don't want to.")
				break

	def filter_request(self):
		logging.debug("Filtering the request.")
		for f in self.__filter_request:
			if f(self):
				self.set_response_forbidden(reason="I don't want to.")
				break



if __name__ == "__main__":

	logging.basicConfig(format='%(levelname)8s:%(asctime)s:%(funcName)20s():%(message)s',
	                    filename='proxy.log', level=logging.DEBUG)


	cherryproxy.main(FilteringProxy)
	# proxy = FilteringProxy(address='localhost', port=8000,
	#                        server_name='grenzubergang-Proxy',
	#                        debug=True, log_level=0, options=None,
	#                        parent_proxy=None)

	# try:
	# 	proxy.start()
	# except KeyboardInterrupt:
	# 	proxy.stop()
