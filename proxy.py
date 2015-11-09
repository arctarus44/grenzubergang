#!/usr/bin/env python2

"""This module implement a proxy that seek to detect and block http tunnel
used to transport SSH protocole.

Disclaimer : this is a student work. If you want use something that might
not work, use this module."""

import cherryproxy
import base64
from BeautifulSoup import BeautifulSoup
import threading as thread
import logging
import json
from ast import literal_eval
import time
from math import floor


INLINE = ["span", "b", "big", "i", "small", "tt", "abbr", "acronym", "cite",
          "code", "dfn", "em", "kbd", "strong", "samp", "var", "a",
          "img", "map", "object", "q", "script", "sub", "sup", "label"]


CACHE_DURATION = 5


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
	# raise TypeError("{} is not base64/32/16 encoded string".format(string))


def decode_string(string):
	""" Test if a string contains the keyword 'SSH' """
	if 'ssh' in string or 'SSH' in string:
		return True
	return False


# def extract_payload(html):
# 	"""Extract a payload from an html page."""

# 	def inline_gen(html):
# 		"""Extract from every inline element the content."""
# 		parser = BeautifulSoup(html, 'html.parser')
# 		for element in INLINE:
# 			elements = parser.findAll(element)
# 			inline = ""
# 			for tag in elements:
# 				inline += tag.next
# 			yield inline

# 	for payload in inline_gen(html):
# 		if decode_baseX(payload) != None:
# 			return payload
# 	return None



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
	except KeyError:
		return True
	else:
		for agent in agents:
			if agent in user_agent:
				return True
	return False

#store the result of a GET request
# client[full_url] = (time, data)
cache = {}

def response_data_cache(proxy):
	if not "GET" in proxy.req.method:
		logging.debug("It's not a get")
		return False

	crt_time = time.time()
	cache_policy = CACHE_DURATION + crt_time
	try:
		cache_policy = proxy.req.headers["cache-control"]
	except KeyError:
		logging.debug("No cache policy detected, so we cache the response")
	else:
		if cache_policy in ["max-age=0", "no-store", "no-cache"]:
			logging.debug("The cache policy say we cannot cache the response :(.")
			return False
		else:
			cache_policy = int(cache_policy.replace("max-age=", "")) + crt_time
			logging.debug("We will cached this data for until %s", cache_policy)

	# if the cache is too old, we put store a fresh data.
	try:
		if floor(cache[proxy.req.full_url][0]) - floor(crt_time) > CACHE_DURATION:
			logging.info("Cached response for a GET request on %s until %s",
						 proxy.req.full_url, cache_policy)
			cache[proxy.req.full_url] = (cache_policy, proxy.req.data)
	except KeyError:
		cache[proxy.req.full_url] = (cache_policy, proxy.req.data)
	return False

def request_cache(proxy):
	if not "GET" in proxy.req.method:
		logging.debug("It's not a get")
		return False

	logging.debug("Let's try to find something interresting in the cache for %s"
	              , proxy.req.full_url)
	crt_time = time.time()

	try:
		cache_duration, data = cache[proxy.req.full_url]
	except KeyError:
		logging.debug("Nothing stored for %s", proxy.req.full_url)
		return False
	else:
		logging.debug("Something stored for %s", proxy.req.full_url)
		if floor(cache[proxy.req.full_url][0]) - floor(crt_time) < CACHE_DURATION:
			logging.info("@@@ fresh data to send")
			proxy.set_response(status=proxy.resp.status, data=data)
		else:
			logging.info("&&& fresh data to send")
			return False



# Request
def filter_request_ssh(proxy):
	logging.debug("Searching a string ssh...")

	def has_ssh(data):
		""" Search the string "SSH" in the data, then return True or False."""
		decoded = decode_baseX(data)
		if decoded != None and 'SSH' in decoded:
			return True
		else:
			return False

	def has_ssh_list(data, reverse=False):
		""" Sort the key and check if the ssh string is present. If reverse
		equal True, the keys are sort in decroissant order."""
		keys.sort(reverse=reverse)
		payload = ""
		for k in keys:
			payload += data[k]

		return has_ssh(payload)

	if "GET" in proxy.req.method:
		logging.debug("GET request received.")
		payload = proxy.req.url[1:]
		logging.debug("Payload = %s", payload)
		if has_ssh(payload):
			logging.debug("Blocking the request %s.", proxy.req.full_url)
			return True
		return False


	elif "POST" in proxy.req.method:
		logging.debug("POST data received : %s.", proxy.req.data)
		try:
			data = literal_eval(proxy.req.data)
			print data
		except SyntaxError: # If it's not a JSON
			if has_ssh(proxy.req.data): # it's a string
				logging.debug("Blocking the request %s with the following payload %s.",
				              proxy.req.full_url, proxy.req.data)
				return True
			return False
		except ValueError as e:
			logging.error(e)
			logging.debug("AZERTYUIOPAZERTYUIO")
			if has_ssh(proxy.req.data): # it's a string
				logging.debug("Blocking the request %s with the following payload %s.",
				              proxy.req.full_url, proxy.req.data)
				return True
			return False

		except Exception as e:
			logging.debug("AZERTYUIOPAZERTYUIO")
			logging.exception(e)
			return False

		else: # it's a JSON and we have a mapping object
			logging.debug("It's a JSON")
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

def info(proxy):
	print dir(proxy.resp)



class FilteringProxy(cherryproxy.CherryProxy):

	__filter_header = [filter_header_user_agent]
	__filter_response = [response_data_cache]
	__filter_request = [request_cache, filter_request_ssh]

	# def filter_request_headers(self):
	# 	logging.debug("Filtering the headers.")
	# 	for f in self.__filter_header:
	# 		if f(self):
	# 			self.set_response_forbidden(reason="I don't want to.")
	# 			break

	def filter_request(self):
		logging.debug("Filtering the request.")
		for f in self.__filter_request:
			if f(self):
				self.set_response_forbidden(status=403, reason="I don't want to.")
				break
		logging.debug("Forwarding the request.")

	def filter_response(self):
		logging.debug("New reponse received")
		for f in self.__filter_response:
			if f(self):
				self.set_response_forbidden(status=403, reason="I don't want to.")
				break
		logging.debug("Forwarding the request.")


if __name__ == "__main__":

	logging.basicConfig(format='%(levelname)8s:%(asctime)s:%(funcName)20s():%(message)s',
	                    filename='proxy.log', level=logging.DEBUG)

	cherryproxy.main(FilteringProxy)
