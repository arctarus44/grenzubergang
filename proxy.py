#!/usr/bin/env python2

import cherryproxy
import base64
from BeautifulSoup import BeautifulSoup
import threading as thread

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
def filter_request_ssh(data):
	try:
		if 'SSH' in decode_baseX(data):
			print "SSH READ"
			return True
		else:
			"PASS: not SSH"
			return False
	except TypeError:
		print "WRONG TYPE TO CHECK SSH"
		return False


################################## The Proxy ###################################

class FilteringProxy(cherryproxy.CherryProxy):

	__filter_header = [] #filter_header_random
	__filter_response = []
	__filter_request = [filter_request_ssh]

	def filter_request_headers(self):
		headers = self.req.headers
		print("|" + self.__mro__ )
		# print(self.resp.httpconn)print(dir(self.resp.httpconn))
		for f in self.__filter_header:
			if f(self):
				self.set_response_forbidden(reason="I don't want to.")
				break


	def filter_request(self):
		if 'GET' in self.req.method:
			url = self.req.url
			url = list(url)
			url[0] = ''
			url = "".join(url)
			url = url.split('/')
			for path in url:
				print path
				if filter_request_ssh(path):
					print "T'as voulu faire quoi la ?"
					self.set_response_forbidden(reason="Are you serious ? SSH in HTTP ? :)")
					return
				reverse_path = path[::-1]
				if filter_request_ssh(reverse_path):
					print "Meme en inverse je te baise :)"
					self.set_response_forbidden(reason="Too low in reverse :)")
					return
		else:
			print "------- BEGIN DATA -------"
			#data = self.req.data
			length = int(self.req.length)
			data = urlparse.parse_qs(self.req.data)
			print data
			print "------- END DATA -------" 
			for f in self.__filter_request:
				if f(data):
					print "The keyword 'SSH' has been read"
					self.set_response_forbidden(reason="Are you serious ? SSH in HTTP ? :)")
					break


if __name__ == "__main__":

	cherryproxy.main(FilteringProxy)
	# proxy = FilteringProxy(address='localhost', port=8000,
	#                        server_name='grenzubergang-Proxy',
	#                        debug=True, log_level=0, options=None,
	#                        parent_proxy=None)

	# try:
	# 	proxy.start()
	# except KeyboardInterrupt:
	# 	proxy.stop()
