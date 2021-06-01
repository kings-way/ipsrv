#!/usr/bin/env python3
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

from flask import abort
from flask import request
from flask import jsonify
from flask import render_template
from subprocess import Popen,PIPE
import xml.etree.cElementTree as ET


ASN_reader = None
CITY_reader = None
bing_wallpaper_updated_time = 0
bing_wallpaper_url = [None, None, None]

visitors = {}   # {"ip":(timestamp, count)}
requests_session = requests.session()

amap_ip_loc_api   = 'http://restapi.amap.com/v4/ip?key={}&ip={}'    # this API does not support keep-alive
amap_location_api = 'http://ditu.amap.com/service/regeo?latitude={}&longitude={}'

# [bts]     format: mcc,mnc,lac,cellid,rssi
# [nearbts] format: bts1|bts2|bts3  (it's optional)
#           example: bts=460,01,6180,184591471,-100
amap_cell_loc_api = 'http://apilocate.amap.com/position?accesstype=0&cdma=0&key={}&bts={}'

# [macs]    format: mac|mac|mac, shall have at least 2 mac_addr
# [mac]     format: essid,rssi,ssid
#           example: b4:5d:50:01:ff:07,-60,SSID1|68:d7:9a:3e:7d:12,-60,SSID2
amap_wifi_loc_api = 'http://apilocate.amap.com/position?accesstype=1&key={}&macs={}'


def update_global_var(now_time):
    global bing_wallpaper_updated_time
    if (now_time -  bing_wallpaper_updated_time) > 7200:
        bing_wallpaper_updated_time = now_time

        # Update Geoip Reader
        global CITY_reader
        global ASN_reader
        global bing_wallpaper_url
        CITY_reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb')
        ASN_reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-ASN.mmdb')

        # Update Bing Wallpaper
        bing_url = "https://cn.bing.com/HPImageArchive.aspx?idx=0&n=3"
        resp = requests.get(bing_url)
        if not resp.ok:
            return
        tree = ET.fromstring(resp.text.encode('utf8'))
        for i in range(0,3):
            bing_wallpaper_url[i] = ['http://cn.bing.com/' + tree[i][4].text + '_1920x1080.jpg', tree[i][5].text]


def get_wifi_cell_location(data, is_wifi, is_cell):
    global requests_session
    global amap_wifi_loc_api
    global amap_cell_loc_api

    api = ''
    if is_wifi:
        api = amap_wifi_loc_api.format(API_KEY_AMAP, '|'.join(data))
    elif is_cell:
        api = amap_cell_loc_api.format(API_KEY_AMAP, data[0])
        if len(data) > 1:
            api += '&nearbts=' + '|'.join(data[1:])
    else:
        return -1, "no wifi and no cell, what's your problem?"
    try:
        resp = requests_session.get(api, timeout=3)
    except requests.exceptions.Timeout as _:
        return -1, "Upstream API request timeout, url: [%s]" % api.split('?')[0]

    if not resp.ok:
        return -1, "Upstream API http status error: %d, url: [%s] " % \
                    (resp.status_code, resp.url.split('?')[0])

    data = resp.json()
    if data['status'] != '1' :
        return -1, "Upstream API returns error: errcode: %d, errmsg: %s, url: %s" % \
                    (data['errcode'], data['errmsg'], resp.url.split('?')[0])

    if data['result']['type'] == '0':
        return -2, "Upsteam API returns empty result"

    result = data['result']
    return 0, dict( city      = result['province'] + ',' + result['city'],
                    location  = result['desc'],
                    latitude  = result['location'].split(',')[1],
                    longitude = result['location'].split(',')[0],
                    radius    = result['radius'])

def get_longitude_latitude(ip):
    global requests_session
    global amap_ip_loc_api
    try:
        resp = requests_session.get(amap_ip_loc_api.format(API_KEY_AMAP, ip), timeout=3)
    except requests.exceptions.Timeout as _:
        return -1, "Upstream API request timeout, url: [%s]" % amap_ip_loc_api.split('?')[0]

    if not resp.ok:
        return -1, "Upstream API http status error: %d, url: [%s] " % \
                    (resp.status_code, resp.url.split('?')[0])

    data = resp.json()
    if data['errcode'] != 0 :
        return -1, "Upstream API returns error: errcode: %d, errmsg: %s, url: %s" % \
                    (data['errcode'], data['errmsg'], resp.url.split('?')[0])

    return 0, (data['data']['lat'], data['data']['lng'], data['data']['confidence'])


def get_high_precision_location(ip):
    global requests_session
    global amap_location_api
    ret = get_longitude_latitude(ip)
    if ret[0] == -1:
        return ret
    try:
        resp = requests_session.get(amap_location_api.format(ret[1][0], ret[1][1]), timeout=3)
    except requests.exceptions.Timeout as _:
        return -1, "Upstream API request timeout, url: [%s]" % amap_location_api.split('?')[0]

    if not resp.ok:
        return -1, "Upstream API http status error: %d, url: [%s] " % \
                    (resp.status_code, resp.url.split('?')[0])

    data = resp.json()['data']
    if data['result'] != 'true':
        return -1, "Upstream API returns error: message: %s, url: %s" % \
                    (data['message'], resp.url.split('?')[0])
    return 0, dict(city=data['desc'], position=data['pos'],
                    latitude=ret[1][0], longitude=ret[1][1],
                    confidence=ret[1][2])


High_Precision_Failure  = dict(city='-', position='-', latitude=0, longitude=0, confidence=2333)

def do_query_ip_hostname(hostname, ipv6=False):
    global High_Precision_Failure

    # if there is more than two ':' in hostname, then this may be a valid ipv6 address already
    IP = None
    if hostname.count(':') >1:
        ipv6 = True
        IP = hostname
    else:
        try:
            IP = socket.getaddrinfo(hostname, None, socket.AF_INET)[0][4][0]
        except socket.gaierror:
            try:
                IP = socket.getaddrinfo(hostname, None, socket.AF_INET6)[0][4][0]
            except Exception:
                pass
        except Exception:
                pass

        if IP is None:
            return dict(IP=hostname + " (Can't resolve hostname)", ISP='', ASN='', City='',
                        Country='', Location='', High=High_Precision_Failure )
    try:
        ASN = ASN_reader.asn(IP)
        ISP = ASN.autonomous_system_organization
        ASN = 'AS' + str(ASN.autonomous_system_number)
        ISP = 'ChinaNET' if ISP =='No.31,Jin-rong Street' else ISP
    except (geoip2.errors.AddressNotFoundError, ValueError) as e:
        # not found
        ASN = ISP = '-'

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
            if 'zh-CN' in City.city.names:
                city_name_zh = City.city.names['zh-CN']

        if City.subdivisions.most_specific.name is not None:
            city_name_en += ', ' + City.subdivisions.most_specific.names['en']
            if 'zh-CN' in City.subdivisions.most_specific.names:
                city_name_zh += ', ' + City.subdivisions.most_specific.names['zh-CN']

        City = "" if city_name_en == "" else "%s | %s" % (city_name_en.strip(', '), city_name_zh.strip(', '))

    except (geoip2.errors.AddressNotFoundError, ValueError) as e:
        # not found
        Location = City = Country = '-'

    # High Precision Location
    ret, high_precision_location = get_high_precision_location(IP)
    if ret == -1:
        print(high_precision_location)
        high_precision_location = High_Precision_Failure
#    if not ipv6:
#        ret, high_precision_location = get_high_precision_location(IP)
#        if ret == -1:
#            high_precision_location = High_Precision_Failure
#    else:
#        high_precision_location = High_Precision_Failure


    IP = IP if IP == hostname else hostname + ' (' + IP + ')'
    return dict(IP=IP , ISP=ISP, ASN=ASN, City=City, Country=Country, Location=Location, High=high_precision_location)

# Do some security check work, like check the ip format
def is_secure(string):
	return True

def query_wifi_cell_location(data, ua, is_wifi=False, is_cell=False):
    ua = str(ua).lower()
    ret, data = get_wifi_cell_location(data, is_wifi, is_cell)
    if ret == -1:
        print(data)
        return "error"
    elif ret == -2:
        city = '-'
        location = '-'
        radius = '-'
        coordinates = '-'
    else:
        city = data['city']
        location = data['location']
        radius = data['radius'] + ' (m)'
        coordinates = data['latitude'] + ', ' + data['longitude']

    return  'City:        {}\n'\
            'Location:    {}\n'\
            'Coordinates: {}\n'\
            'Radius:      {}\n'\
            .format(city, location, coordinates, radius)


def query_ip_hostname(hostname, plaintext=True):
    now_time = int(time.time())
    update_global_var(now_time)
    data = do_query_ip_hostname(hostname)
    High_Preci_Coordinates = "-" if data['High']['confidence'] == 2333 else "%.4f, %.4f (confidence: %.2f)" % \
                                     (data['High']['latitude'],data['High']['longitude'],data['High']['confidence'])
    data['High_Preci_Coordinates'] = High_Preci_Coordinates

    if plaintext:
        return  'IP:      {}\n'\
                'ASN:     {}\n'\
                'ISP:     {}\n'\
                'City:    {}\n'\
                'Country: {}\n'\
                'Geo Loc: {}\n\n'\
                'IP City:        {}\n'\
                'IP Location:    {}\n'\
                'IP Coordinates: {}\n'.format(
                    data['IP'],
                    data['ASN'],
                    data['ISP'],
                    data['City'],
                    data['Country'],
                    data['Location'],
                    data['High']['city'],
                    data['High']['position'],
                    data['High_Preci_Coordinates']
                    )
    else:
        return render_template('index.html', wallpaper=bing_wallpaper_url[now_time % 3])


def check_req_freq_ok(ip):
    global visitors

    now_time = int(time.time())
    record = visitors.get(ip)

    if record is not None:
        last_time, count = record
        # if more than 5 mins, return OK
        if now_time - last_time > 300:
            visitors[ip] = (now_time, 1)
            return True

        # if less than 5 mins, check request count
        else:
            visitors[ip] = (now_time, count+1)
            if count < 20:
                return True
            else:
                return False
    else:
        visitors[ip] = (now_time, 1)
        return True


@app.route('/favicon.ico')
def favicon():
    abort(404)

# params can be DomainName, IP, IPv6
@app.route('/', methods=['GET'])
@app.route('/<args>', methods=['GET'])
@app.route('/ip/<args>', methods=['GET'])
def route_ip_hostname(args=None):
    if args is None or args == 'localhost':
        headers_list = request.headers.getlist("X-Forwarded-For")
        hostname = headers_list[0].split(',')[0] if headers_list else request.remote_addr
    else:
        hostname = args

    ua = str(request.user_agent).lower();
    plaintext = 'curl' in ua or 'wget' in ua or request.path.startswith('/ip/');
    return query_ip_hostname(hostname, plaintext)


# params: /wifi/essid1,rssi1|essid2,rssi2|....
@app.route('/wifi/<args>', methods=['GET'])
def route_wifi_location(args):
    # need to take care of Cloudflare Proxy-ed Request
    if not check_req_freq_ok(request.remote_addr):
        abort(429, "request too fast, ip: %s" % request.remote_addr)

    essids = []
    for i in args.split('|'):
        if len(i.split(',')) == 2:
            essids.append(i + ',NoSSID')
        else:
            abort(500, 'wrong params')
    if len(essids) == 0:
        abort(500, 'wrong params')
    elif len(essids) == 1:
        essids.append("ff:ff:ff:ff:ff:ff,-60,NoSSID")

    return query_wifi_cell_location(essids, request.user_agent, is_wifi=True)

# params: /cell/mcc,mnc,lac,cellid,rssi|mcc,mnc,lac,cellid,rssi
# the first is connected cell station, the others are nearby stations
@app.route('/cell/<args>', methods=['GET'])
def route_cell_location(args):
    # need to take care of Cloudflare Proxy-ed Request
    if not check_req_freq_ok(request.remote_addr):
        abort(429, "request too fast, ip: %s" % request.remote_addr)

    bts = []
    for i in args.split('|'):
        if len(i.split(',')) == 5:
            bts.append(i)
        else:
            abort(500, 'wrong params')
    if len(bts) > 0:
        return query_wifi_cell_location(bts, request.user_agent, is_cell=True)
    else:
        abort(500, 'wrong params')
