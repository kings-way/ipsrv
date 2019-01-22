#!/usr/bin/env python
#encoding=utf8

import re
import time
import types
import socket
import requests
import geoip2.database
from ipsrv import app
from flask import request
from flask import jsonify
from flask import render_template
from subprocess import Popen,PIPE
import xml.etree.cElementTree as ET


bing_wallpaper_url = [0, [], [], []]

CITY_reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb')
ASN_reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-ASN.mmdb')

def get_wallpaper_url():
	global bing_wallpaper_url
	now_time = int(time.time())
	# if the more than 24 hours, we refresh it.
	if (now_time - bing_wallpaper_url[0]) < 7200:
		pass
	else:
		bing_url = "http://cn.bing.com/HPImageArchive.aspx?idx=0&n=3"
		response = requests.get(bing_url)
		if not response.ok:
			return
		tree = ET.fromstring(response.text.encode('utf8'))
		bing_wallpaper_url[0] = int(time.time())
		for i in range(0,3):
			bing_wallpaper_url[i+1] = ['http://cn.bing.com' + tree[i][4].text + '_1920x1080.jpg', tree[i][5].text]

	return bing_wallpaper_url[(now_time%3)+1]


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

def run_addr_geoip2(hostname, ipv6=False):
	# if there is more than 2 ':' in hostname, then this may be a valid ipv6 address already	
	if hostname.count(':') >1:
		ipv6 = True
	else:
		try:
			IP = socket.getaddrinfo(hostname, None, socket.AF_INET)[0][4][0]
		except socket.gaierror, e:
			try:
				IP = socket.getaddrinfo(hostname, None, socket.AF_INET6)[0][4][0]
			except socket.gaierror, e:
				return dict(IP=hostname + " (Can't resolve hostname)", ISP='', ASN='', City='', Country='')
	try:
		ASN = ASN_reader.asn(IP)
		ISP = ASN.autonomous_system_organization
		ASN = 'AS' + str(ASN.autonomous_system_number)
		ISP = 'ChinaNET' if ISP =='No.31,Jin-rong Street' else ISP
	except geoip2.errors.AddressNotFoundError,e:
		ASN = ISP = 'not found'

	try:
		City = CITY_reader.city(IP)
		Location = '' if City.location.latitude is None else "%s, %s" % (City.location.latitude, City.location.longitude)
		Country = '' if City.country.iso_code is None else "%s | %s | %s" % \
					(City.country.iso_code, City.country.names['en'], City.country.names['zh-CN'])

		# City.city.names ==> City Name
		# City.subdivisions.most_specific.names ==> Provice Name
		if City.city.name is not None:
			city_name_en = City.city.names['en'] + ', ' + City.subdivisions.most_specific.names['en']
			city_name_zh = City.city.names['zh-CN'] + ', ' + City.subdivisions.most_specific.names['zh-CN']
		elif City.subdivisions.most_specific.name is not None:
			city_name_en = City.subdivisions.most_specific.names['en']
			city_name_zh = City.subdivisions.most_specific.names['zh-CN']
		else:
			city_name_en = None
			city_name_zh = None

		if city_name_en is None:
			City = ''
		else:
			City = "%s | %s" % (city_name_en, city_name_zh)

	except geoip2.errors.AddressNotFoundError,e:
		Location = City = Country = 'not found'

	IP = IP if IP == hostname else hostname + ' (' + IP + ') '

	return dict(IP=IP , ISP=ISP, ASN=ASN, City=City, Country=Country, Location=Location)

# Do some security check work, like check the ip format
def is_secure(string):
	return True

def run(hostname, ua):
	ua = str(ua).lower()
#	data = run_addr_legacy(hostname)
#	# if the hostname resolv failed, we try resolv AAAA records by geoiplookup6
#	if "Can't resolve hostname" in data['IP']:
#		data = run_addr_legacy(hostname, ipv6=True)
	data = run_addr_geoip2(hostname)
	if 'curl' in ua or 'wget' in ua:
		return 'IP:      %s\nASN:     %s\nISP:     %s\nCity:    %s\nCountry: %s' %\
				(data['IP'], data['ASN'], data['ISP'], data['City'], data['Country'])
	else:
		return render_template('index.html', data=data, wallpaper=get_wallpaper_url())

@app.route('/', methods=['GET'])
def index():
	return run(request.remote_addr, request.user_agent)

@app.route('/<args>', methods=['GET'])
# args can be DomainName, IP, IPv6, ASN
def index2(args):
	# TODO: Check ASN format, and find a way to query ASN info
	#if args is ASN:
	#	return run_asn(args,request.header)
	#else:
	return run(args, request.user_agent)
