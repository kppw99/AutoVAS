#!/usr/bin/env python3

from cpgclient.CpgClient import CpgClient

'''
server = '127.0.0.1'
port = 8080

client = CpgClient(server, port)
client.create_cpg('/home/kevin/works/autoVAS/dataset/source/NVD/cve-2004-1151')

#query = 'cpg.method.name("free").parameter.argument.reachableByFlows(cpg.identifier).l'
query = 'cpg.method.toJson'
method = client.query(query)

print(method)
'''

class AutoVAS:
	def __init__(self):
		self.server = '127.0.0.1'
		self.port = 8080
		self.client = CpgClient(self.server, self.port)

	def __del__(self):
		self.server = '0.0.0.0'
		self.port = 0

	def autoVAS_parse(self, source):
		self.client.create_cpg(source)

	def autoVAS_query(self, query):
		result = self.client.query(query)
		return result


if __name__ == '__main__':
	av = AutoVAS()
	av.autoVAS_parse('/home/kevin/works/autoVAS/dataset/source/NVD/cve-2004-1151')
	print(av.autoVAS_query('cpg.method.name.toSet'))
	print(av.autoVAS_query('cpg.local.name.toSet'))
	del av
