import cherryproxy

class FilteringProxy(cherryproxy.CherryProxy):

	def filter_request(self):
		pass

	def filter_request_headers(self):
		pass



if __name__ == "__main__":

	proxy = FilteringProxy(address='localhost', port=8000,
	                       server_name='grenzubergang-Proxy',
	                       debug=True, log_level=20, options=None,
	                       parent_proxy=None)

	proxy.start()
