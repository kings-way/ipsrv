#!/usr/bin/env python
#encoding=utf8

import re
import pdb
import time
import types
import socket
import requests
import geoip2.database
from ipsrv import app
from ipsrv.conf.conf import *

from flask import request
from flask import jsonify
from flask import render_template
from subprocess import Popen,PIPE
import xml.etree.cElementTree as ET


updated_time = 0
bing_wallpaper_url = [None, None, None]
CITY_reader = None
ASN_reader = None

def update_global_var(now_time):
    global updated_time
    if (now_time -  updated_time) > 7200:
        updated_time = now_time

        # Update Geoip Reader
        global CITY_reader
        global ASN_reader
        global bing_wallpaper_url
        CITY_reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb')
        ASN_reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-ASN.mmdb')

        # Update Bing Wallpaper
        bing_url = "http://cn.bing.com/HPImageArchive.aspx?idx=0&n=3"
        response = requests.get(bing_url)
        if not response.ok:
            return
        tree = ET.fromstring(response.text.encode('utf8'))
        for i in range(0,3):
            bing_wallpaper_url[i] = ['http://cn.bing.com' + tree[i][4].text + '_1920x1080.jpg', tree[i][5].text]


def get_longitude_latitude(ip):
    amap_api_url = 'https://restapi.amap.com/v4/ip?key={}&ip={}'
    response = requests.get(amap_api_url.format(API_KEY_AMAP, ip))
    if not response.ok:
        return -1, "AMAP API '/ip' HTTP CODE ERROR: " + str(response.status_code);
    data = response.json()
    if data['errcode'] !=0 :
        return -1, "AMAP API '/ip' ERROR: " + data['errmsg']
    return 0, (data['data']['lat'], data['data']['lng'], data['data']['confidence'])

def get_high_precision_location(ip):
    ret = get_longitude_latitude(ip)
    if ret[0] == -1:
        return ret
    amap_location_api_url = 'https://ditu.amap.com/service/regeo?latitude={}&longitude={}'
    response = requests.get(amap_location_api_url.format(ret[1][0], ret[1][1]))
    if not response.ok:
        return -1, "AMAP API '/regeo' HTTP CODE ERROR: " + str(response.status_code)
    data = response.json()['data']
    if data['result'] != 'true':
        return -1, "AMAP API '/regeo' ERROR: " + data['message']

    return 0, dict(city=data['desc'], position=data['pos'],
                    latitude=ret[1][0], longitude=ret[1][1],
                    confidence=ret[1][2])


def run_addr_geoip2(hostname, ipv6=False):
    high_precision_location_default = dict(city='', position='', latitude=0, longitude=0, confidence=2333)

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
                return dict(IP=hostname + " (Can't resolve hostname)", ISP='', ASN='', City='', Country='',
                       High=high_precision_location_default )
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
        city_name_en = ''
        city_name_zh = ''
        if City.city.name is not None :
            city_name_en = City.city.names['en']
            if City.city.names.has_key('zh-CN'):
                city_name_zh = City.city.names['zh-CN']

        if City.subdivisions.most_specific.name is not None:
            city_name_en += ', ' + City.subdivisions.most_specific.names['en']
            if City.subdivisions.most_specific.names.has_key('zh-CN'):
                city_name_zh += ', ' + City.subdivisions.most_specific.names['zh-CN']

        City = "" if city_name_en is "" else "%s | %s" % (city_name_en.strip(', '), city_name_zh.strip(', '))

    except geoip2.errors.AddressNotFoundError,e:
        Location = City = Country = 'not found'

    # High Precision Location
    if not ipv6:
        ret, high_precision_location = get_high_precision_location(IP)
        if ret == -1:
            high_precision_location = high_precision_location_default
    else:
        high_precision_location = high_precision_location_default


    IP = IP if IP == hostname else hostname + ' (' + IP + ')'
    return dict(IP=IP , ISP=ISP, ASN=ASN, City=City, Country=Country, Location=Location, High=high_precision_location)

# Do some security check work, like check the ip format
def is_secure(string):
	return True

def run(hostname, ua):
    ua = str(ua).lower()
    now_time = int(time.time())
#   data = run_addr_legacy(hostname)
#   # if the hostname resolv failed, we try resolv AAAA records by geoiplookup6
#   if "Can't resolve hostname" in data['IP']:
#       data = run_addr_legacy(hostname, ipv6=True)
    update_global_var(now_time)
    data = run_addr_geoip2(hostname)
    High_Preci_Loc_Str = "" if data['High']['confidence'] == 2333 else "%.4f,%.4f (可信度: %.2f)" % \
                                     (data['High']['latitude'],data['High']['longitude'],data['High']['confidence'])

    data['High_Preci_Loc_Str'] = High_Preci_Loc_Str.decode('utf8')

    if 'curl' in ua or 'wget' in ua:
        return '\
IP:      {}\n\
ASN:     {}\n\
ISP:     {}\n\
City:    {}\n\
Country: {}\n\
Geo Loc: {}\n\n\
IP 地区: {}\n\
IP 位置: {}\n\
IP 坐标: {}\n'.format(\
                    data['IP'].encode('utf8'),
                    data['ASN'].encode('utf8'),
                    data['ISP'].encode('utf8'),
                    data['City'].encode('utf8'),
                    data['Country'].encode('utf8'),
                    data['Location'].encode('utf8'),
                    data['High']['city'].encode('utf8'),
                    data['High']['position'].encode('utf8'),
                    data['High_Preci_Loc_Str'].encode('utf8')
                    )
    else:
        return render_template('index.html', data=data, wallpaper=bing_wallpaper_url[now_time % 3])

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
