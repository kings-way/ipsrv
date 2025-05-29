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
from flask import send_from_directory
from subprocess import Popen,PIPE


ASN_reader = None
CITY_reader = None
global_var_updated_time = 0
bing_wallpaper_url = [None, None, None]

visitors = {}   # {"ip":(timestamp, count)}
requests_session = requests.session()

amap_ip_loc_api   = 'http://restapi.amap.com/v3/ip?key={}&ip={}'    # IP location V3, only to city range
#amap_ip_loc_api   = 'http://restapi.amap.com/v4/ip?key={}&ip={}'    # IP location V4, seems disabled (no keep-alive)
#amap_ip_loc_api   = 'https://restapi.amap.com/v5/ip/location?key={}&ip={}&type=4'    # IP location V5, amap + ipplus360
amap_ip_loc_web   = 'https://webapi.amap.com/maps/ipLocation?key={}&callback=jsonp_1234' # IP location for js sdk, seems no help
amap_location_api = 'http://ditu.amap.com/service/regeo?latitude={}&longitude={}'

# [bts]     format: mcc,mnc,lac,cellid,rssi
# [nearbts] format: bts1|bts2|bts3  (it's optional)
#           example: bts=460,01,6180,184591471,-100
amap_cell_loc_api = 'http://apilocate.amap.com/position?accesstype=0&cdma=0&key={}&bts={}'

# [macs]    format: mac|mac|mac, shall have at least 2 mac_addr
# [mac]     format: essid,rssi,ssid
#           example: b4:5d:50:01:ff:07,-60,SSID1|68:d7:9a:3e:7d:12,-60,SSID2
amap_wifi_loc_api = 'http://apilocate.amap.com/position?accesstype=1&key={}&macs={}'

bing_wallpaper_api = "https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=3"


def update_global_var():
    global bing_wallpaper_url
    global global_var_updated_time
    now_time = int(time.time())
    if (now_time -  global_var_updated_time) > 7200:
        global_var_updated_time = now_time

        # Update Geoip Reader
        global CITY_reader
        global ASN_reader
        CITY_reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb')
        ASN_reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-ASN.mmdb')

        # Update bing wallpaper
        resp = requests.get(bing_wallpaper_api)
        if not resp.ok:
            return
        else:
            bing_wallpaper_url.clear()
            for line in resp.json()['images']:
                bing_wallpaper_url.append(dict(url='http://cn.bing.com/' + line['url'], copyright=line['copyright']))

# call update_global_var() once on start
update_global_var()

def get_wifi_cell_location(data, is_wifi, is_cell):
    global requests_session
    global amap_wifi_loc_api
    global amap_cell_loc_api

    api = ''
    if is_wifi:
        api = amap_wifi_loc_api.format(API_KEY_AMAP_IoT, '|'.join(data))
    elif is_cell:
        api = amap_cell_loc_api.format(API_KEY_AMAP_IoT, data[0])
        if len(data) > 1:
            api += '&nearbts=' + '|'.join(data[1:])
    else:
        return -1, "not querying wifi or cell, what's your problem?"
    try:
        resp = requests_session.get(api, timeout=3)
    except requests.exceptions.Timeout as _:
        return -1, "Upstream API request timeout, url: [%s]" % api.split('?')[0]
    except Exception as e:
        return -1, "Upstream API request failed, url: [%s]\n[%s]" % (api.split('?')[0], str(e))

    if not resp.ok:
        return -1, "Upstream API http status error: %d, url: [%s] " % \
                    (resp.status_code, resp.url.split('?')[0])

    data = resp.json()
    if data['status'] != '1' :
        try:
            return -1, "Upstream API result error: code: %d, msg: %s, url: %s" % \
                    (data['errcode'], data['errmsg'], resp.url.split('?')[0])
        except KeyError as e:
            return -1, "Upstream API result error: %s" % data['info']

    if data['result']['type'] == '0':
        return -2, "Upsteam API returns empty result"

    result = data['result']
    return 0, dict( city      = result['province'] + ',' + result['city'],
                    location  = result['desc'],
                    latitude  = result['location'].split(',')[1],
                    longitude = result['location'].split(',')[0],
                    radius    = result['radius'])

def get_ip_location(ip):
    global requests_session
    global amap_ip_loc_api
    try:
        resp = requests_session.get(amap_ip_loc_api.format(API_KEY_AMAP_IP, ip), timeout=3)
    except requests.exceptions.Timeout as _:
        return -1, "Upstream API request timeout, url: [%s]" % amap_ip_loc_api.split('?')[0]
    except Exception as e:
        return -1, "Upstream API request failed, url: [%s]\n[%s]" % (amap_ip_loc_api.split('?')[0], str(e))

    if not resp.ok:
        return -1, "Upstream API http status error: %d, url: [%s] " % \
                    (resp.status_code, resp.url.split('?')[0])

    data = resp.json()

    # for amap ip api v4, return the coordinates
    if 'errcode' in data.keys():
        if data['errcode'] != 0:
            return -2, "Upstream API result error: code: %d, msg: %s, url: %s" % \
                    (data['errcode'], data['errmsg'], resp.url.split('?')[0])
        return 0, (data['data']['lat'], data['data']['lng'], data['data']['confidence'])

    # for amap ip api v3, return the city directly
    if 'status' in data.keys():
        if data['status'] == "0":
            return -2, "Upstream API result error: code: %s, msg: %s, url: %s" % \
                    (data['infocode'], data['info'], resp.url.split('?')[0])
        if len(data['province']) > 0 and len(data['city']) > 0:
            return -3, "{}, {}".format(data['province'], data['city'])
        else:
            return -3, "-"


def get_high_precision_location(ip):
    global requests_session
    global amap_location_api
    ret = get_ip_location(ip)
    if ret[0] == -1 or ret[0] == -2:
        return ret
    # for amap ip api v3
    if ret[0] == -3:
        return 0, dict(city=ret[1], position='-', latitude=0, longitude=0, confidence=2333)

    try:
        resp = requests_session.get(amap_location_api.format(ret[1][0], ret[1][1]), timeout=3)
    except requests.exceptions.Timeout as _:
        return -1, "Upstream API request timeout, url: [%s]" % amap_location_api.split('?')[0]
    except Exception as e:
        return -1, "Upstream API request failed, url: [%s]\n[%s]" % (amap_location_api.split('?')[0], str(e))

    if not resp.ok:
        return -1, "Upstream API http status error: %d, url: [%s] " % \
                    (resp.status_code, resp.url.split('?')[0])

    data = resp.json()['data']
    if data['result'] != 'true':
        return -2, "Upstream API result error: message: %s, url: %s" % \
                    (data['message'], resp.url.split('?')[0])
    return 0, dict(city=data['desc'], position=data['pos'],
                    latitude=ret[1][0], longitude=ret[1][1],
                    confidence=ret[1][2])


def resolve_hostname(hostname):
    IP = None
    is_ipv6 = False
    if hostname.count(':') >1:
        is_ipv6 = True
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
    return IP, is_ipv6


def do_query_ip_info(hostname):
    # if there is more than two ':' in hostname, then this may be a valid ipv6 address already
    IP, is_ipv6 = resolve_hostname(hostname)
    if IP is None:
        return dict(IP=hostname + " (Can't resolve hostname)", ISP='', ASN='', City='',
                    Country='', Location='')
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
        Location = '' if City.location.latitude is None else "%.6f, %.6f" % (City.location.longitude, City.location.latitude)
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

    IP = IP if IP == hostname else hostname + ' (' + IP + ')'
    return dict(IP=IP , ISP=ISP, ASN=ASN, City=City, Country=Country, Location=Location)


High_Precision_Empty    = dict(city='-', position='-', latitude=0, longitude=0, confidence=2333)
High_Precision_Failure  = dict(city='failed', position='failed', latitude=0, longitude=0, confidence=2333)

def do_query_ip_location(hostname):
    global High_Precision_Empty
    global High_Precision_Failure

    IP, is_ipv6 = resolve_hostname(hostname)
    if IP is None or IP == '127.0.0.1':
        high_precision_location = High_Precision_Empty
    else:
        ret, high_precision_location = get_high_precision_location(IP)
        if ret == -1:
            print(high_precision_location)
            high_precision_location = High_Precision_Failure
        elif ret == -2:
            print(high_precision_location)
            high_precision_location = High_Precision_Empty

    return dict(High=high_precision_location)

# Do some security check work, like check the ip format
def is_secure(string):
	return True

def query_wifi_cell_location(data, ua, is_wifi=False, is_cell=False):
    #ua = str(ua).lower()
    ret, data = get_wifi_cell_location(data, is_wifi, is_cell)
    if ret == -1:
        print(data)
        city = 'error'
        location = '-'
        radius = '-'
        coordinates = '-'
    elif ret == -2:
        city = '-'
        location = '-'
        radius = '-'
        coordinates = '-'
    else:
        city = data['city']
        location = data['location']
        radius = data['radius'] + ' (m)'
        coordinates = data['longitude'] + ', ' + data['latitude']

    return  'City:        {}\n'\
            'Location:    {}\n'\
            'Coordinates: {}\n'\
            'Radius:      {}\n'\
            .format(city, location, coordinates, radius)


def query_ip_hostname(hostname, get_ip=True, get_loc=True):
    update_global_var()

    result = ''
    if get_ip:
        data = do_query_ip_info(hostname)
        result += \
            'IP:      {}\n'\
            'ASN:     {}\n'\
            'ISP:     {}\n'\
            'City:    {}\n'\
            'Country: {}\n'\
            'Geo Loc: {}\n\n'.format(data['IP'], data['ASN'], data['ISP'], data['City'], data['Country'], data['Location'])


    if get_loc:
        data  = do_query_ip_location(hostname)
        High_Preci_Coordinates = "-" if data['High']['confidence'] == 2333 else "%.6f, %.6f (confidence: %.2f)" % \
                                        (data['High']['longitude'],data['High']['latitude'],data['High']['confidence'])
        result += \
            'IP City:        {}\n'\
            'IP Location:    {}\n'\
            'IP Coordinates: {}\n'.format(data['High']['city'], data['High']['position'], High_Preci_Coordinates)

    return result


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
def route_ip_hostname(args=None):
    if args is None:
        headers_list = request.headers.getlist("X-Forwarded-For")
        hostname = headers_list[0].split(',')[0] if headers_list else request.remote_addr
    else:
        hostname = args

    ua = str(request.user_agent).lower()
    if 'curl' in ua or 'wget' in ua:
        return query_ip_hostname(hostname)
    else:
        return send_from_directory('static', 'index.html')


# API for web, split Maxmind IP Info and High Precision Location into two apis
@app.route('/ip/info/<args>', methods=['GET'])
@app.route('/ip/loc/<args>', methods=['GET'])
def route_ip_api_info(args):
    if args == 'localhost':
        headers_list = request.headers.getlist("X-Forwarded-For")
        hostname = headers_list[0].split(',')[0] if headers_list else request.remote_addr
    else:
        hostname = args
    if request.path.startswith('/ip/info'):
        return query_ip_hostname(hostname, get_ip=True, get_loc=False)
    elif request.path.startswith('/ip/loc'):
        # need to take care of Cloudflare Proxy-ed Request
        if not check_req_freq_ok(request.remote_addr):
            abort(429, "request too fast, ip: %s" % request.remote_addr)
        else:
            return query_ip_hostname(hostname, get_ip=False, get_loc=True)


#params: /wifi/essid1,rssi1|essid2,rssi2|....
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

@app.route('/api/wallpaper/<int:args>', methods=['GET'])
def route_bing_wallpaper(args):
    return jsonify(bing_wallpaper_url[args % 3])
