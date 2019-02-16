#!/usr/bin/env python
#encoding=utf8

import re
import time
import types
import socket
import requests
import geoip2.database
from ipsrv import app
from ipsrv.conf import *

from flask import request
from flask import jsonify
from flask import render_template
from subprocess import Popen,PIPE
import xml.etree.cElementTree as ET



def run_cmd_geoip_legacy(cmd, shell=False):
	# if cmd is a String, then we convert it into a list
	if isinstance(cmd, types.StringType) and shell == False:
		cmd = cmd.split()
	try:
		p = Popen(cmd, stderr=PIPE, stdout=PIPE, shell=shell)
		out, err = p.communicate()
		returncode = p.returncode
		if err:
			# sys.stderr.write('Error when running cmd:' + str(cmd) + '\n' + err)
			out = err + out + '\t' + str(cmd)
		p.wait()
	except OSError, e:
		returncode = -1
		out = str(e) + '\t' + str(cmd)
	return returncode, out.strip()


def run_addr_legacy(hostname, ipv6=False):
	if not is_secure(hostname):
		return dict(IP="Hostname Error", ISP=None, ASN=None, City=None, Country=None)
	if ipv6 or hostname.count(':') > 1:
		ipv6 = True
		cmd = ['geoiplookup6', hostname]
	else:
		cmd = ['geoiplookup', hostname]

	ret,out = run_cmd_geoip_legacy(cmd, shell=False)

	# for geoiplookup, if it fails, the return value is still 0.
	# And '--' does not end the options
	if ret == -1:
		return dict(IP="Error", ISP=None, ASN=None, City=None, Country=None)
	elif "can't resolve hostname" in out:
		return dict(IP=hostname + " (Can't resolve hostname)", ISP=None, ASN=None, City=None, Country=None)
	else:
		# socket.gethostbyname does not support a timeout option.
		# we just assume that geoiplookup has already resolved the hostname,
		# thus socket.gethostbyname won't be a problem
		try:
			# socket.gethostbyname does not resolve AAAA records
			# IP = str(socket.gethostbyname(hostname))
			if ipv6:
				IP = socket.getaddrinfo(hostname, None, socket.AF_INET6)[0][4][0]
			else:
				IP = socket.getaddrinfo(hostname, None, socket.AF_INET)[0][4][0]

			# if IP != hostname, then the hostname is real domain name
			# else, the hostname is ip address, and we do nothing
			if IP != hostname:
				IP = hostname + ' ( ' + IP + ' )'
			else:
				pass
		except socket.gaierror,e:
			IP = hostname
		try:
			ASN = re.search(r'GeoIP ASNum.*: (AS\d+)\s+(.*)', out).group(1)
			ISP = re.search(r'GeoIP ASNum.*: (AS\d+)\s+(.*)', out).group(2)
			ISP = 'ChinaNET' if ISP =='No.31,Jin-rong Street' else ISP
		except AttributeError,e:
			ASN = ISP = 'not found'

		#City = ''.join(re.findall(r'GeoIP City.*:\s+(.*)', out))
		City = ','.join(''.join(re.findall(r'GeoIP City.*:\s+(.*)', out)).split(',')[2:4]).strip()
		Country = ''.join(re.findall(r'GeoIP Country.*: (.*)', out))

		return dict(IP=IP, ISP=ISP, ASN=ASN, City=City, Country=Country)
