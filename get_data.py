#!/usr/bin/env python3

import logging
import argparse
import json
import os
import re
import socket
import sys
from json import JSONDecodeError

import dns.resolver
import requests
from dns.exception import DNSException
from publicsuffixlist import PublicSuffixList

logger = logging.getLogger('cloudcheck')

IP_ADDR_LIST = {}


def parse_args():

    # Parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('domain', help='Base domain of the university, e.g.: example.com; Required argument.')
    parser.add_argument('--dns-resolver', help="Explicit DNS resolver to use, defaults to system resolver. e.g.: 141.1.1.1", dest='dns_resolver')
    parser.add_argument('--whois', help="Bulk-Whois service to use. Possible options are 'cymru' and 'as59645'. Defaults to 'as59645'.", dest='whois')
    parser.add_argument('--debug', help="Print verbose output for debugging.", dest='debug', action="store_true")
    parser.add_argument(
            '-d', help='Additinal domains of the university; Can receive multiple arguments, e.g.: example.ac.com example.net', dest='add_domains',
            action='append',
            nargs='+'
            )
    parser.add_argument(
            '-m', help='Mail domains of the university; Can receive multiple arguments, e.g.: example.com', dest='mail_domains', action='append', nargs='+'
            )
    parser.add_argument(
            '-l', help='LMS names of the university; Can receive multiple arguments, e.g.: canvas.example.com', dest='lms_domains', action='append', nargs='+'
            )
    parser.add_argument(
            '-o', help='Other names of the university; Can receive multiple arguments, e.g.: survey.cs.example.com', dest='other_domains', action='append',
            nargs='+'
            )
    parser.add_argument('-z', help='Disable check for usage of Video-Chat solutions (Zoom, WebEx, BBB, etc.)', dest='vid_check', action='store_true')
    parser.add_argument('-w', help='Disable check base-domain/www. website hosting.', dest='web_check', action='store_true')
    parser.add_argument('--cache-file', help='Write full data to this file.', dest='cache_file')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.basicConfig(format='%(levelname)8s: [%(lineno)4s] %(message)s', level=logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.WARNING)
    logger.info('Arguments: %s', str(args))

    return args


def get_resolver(dns_resolver):
    # Configure specific resolver if it is configured
    if not dns_resolver:
        logger.info('No nameserver given. Using system resolver.')
        # Setting up default resolver
        the_resolver = dns.resolver.Resolver(configure=True)
    else:
        logger.info('Setting resolver to: %s', dns_resolver)
        try:
            the_resolver = dns.resolver.Resolver(configure=False)
            the_resolver.nameservers = [dns_resolver]
        except (DNSException, ValueError, TypeError) as ex:
            logger.exception('Error setting resolver to %s', dns_resolver)
            sys.exit('ERROR: Could not set resolver')

    # Test resolver
    try:
        if dns_resolver:
            logger.info('Testing resolver: %s', dns_resolver)
        else:
            logger.info('Testing system resolver')
        root_servers = [
            'a.root-servers.net.',
            'b.root-servers.net.',
            'c.root-servers.net.',
            'd.root-servers.net.',
            'e.root-servers.net.',
            'f.root-servers.net.',
            'g.root-servers.net.',
            'h.root-servers.net.',
            'i.root-servers.net.',
            'j.root-servers.net.',
            'k.root-servers.net.',
            'l.root-servers.net.',
            'm.root-servers.net.',
            ]
        res_servers = set()
        r = the_resolver.resolve('.', 'NS')
        for ns in r:
            if str(ns) in root_servers:
                res_servers.add(str(ns))
        if len(root_servers) == len(list(res_servers)):
            if dns_resolver:
                logger.info('Found all %d root-servers at: %s', len(res_servers),  dns_resolver)
            else:
                logger.info('Found all %d root-servers at the system resolver.', len(res_servers))
        else:
            if dns_resolver:
                logger.fatal('Found only %d/%d root-servers at: %s', len(res_servers), len(root_servers), dns_resolver)
            else:
                logger.fatal('Found only %d/%s root-servers at the system resolver.', len(res_servers), len(root_servers))
            sys.exit('ERROR: Please use another resolver; Exiting.')
    except Exception as e:
        logger.fatal('Resolver test failed with %s', str(e))
        sys.exit(2)

    return the_resolver


def check_mail_domains(res, mail_dom):

    for d in mail_dom:
        print('# Getting mail data for', d)
        mail_dom[d]['hosted_at'] = []
        mail_dom[d]['provider'] = []
        mail_dom[d]['ips'] = []
        mail_dom[d]['ips_list'] = []
        mail_dom[d]['dmarc'] = {
            'ruf': [],
            'rua': [],
            }

        try:
            r = res.query(d, 'MX')
            for mx in r:
                mail_dom[d]['mx'].append(str(mx.to_text()).split()[-1])
        except DNSException:
            pass
        try:
            r = res.query('_dmarc.' + d, 'TXT')
            for txt in r:
                for v in str(txt.to_text()).split(';'):
                    if 'ruf' in v:
                        mail_dom[d]['dmarc']['ruf'] = v.split('=')[-1].replace('mailto:', '').split(',')
                    if 'rua' in v:
                        mail_dom[d]['dmarc']['rua'] = v.split('=')[-1].replace('mailto:', '').split(',')
            tmp_ruf = mail_dom[d]['dmarc']['ruf']
            mail_dom[d]['dmarc']['ruf'] = []
            for v in tmp_ruf:
                mail_dom[d]['dmarc']['ruf'].append(v.strip('"'))
            tmp_rua = mail_dom[d]['dmarc']['ruf']
            mail_dom[d]['dmarc']['rua'] = []
            for v in tmp_rua:
                mail_dom[d]['dmarc']['rua'].append(v.strip('"'))
        except (DNSException, ValueError):
            pass
        for mx in mail_dom[d]['mx']:
            ipdata, ips = res_to_ip(res, mx)
            mail_dom[d]['ips'].append(ipdata)
            mail_dom[d]['ips_list'] += ips
            if 'google' in mx or 'gmail' in mx:
                mail_dom[d]['provider'].append('google')
            if 'outlook' in mx or 'exchange' in mx:
                mail_dom[d]['provider'].append('microsoft')
            if 'surfmailfilter' in mx or 'surf.net' in mx:
                mail_dom[d]['provider'].append('surf')
        if mail_dom[d]['dmarc']['rua'] and 'proofpoint' not in mail_dom[d]['provider'] and 'proofpoint_appliance' not in mail_dom[d]['provider']:
            for rua in mail_dom[d]['dmarc']['rua']:
                if 'proofpoint' in rua:
                    mail_dom[d]['provider'].append('proofpoint_appliance')
        if mail_dom[d]['dmarc']['ruf'] and 'proofpoint' not in mail_dom[d]['provider'] and 'proofpoint_appliance' not in mail_dom[d]['provider']:
            for ruf in mail_dom[d]['dmarc']['ruf']:
                if 'proofpoint' in ruf:
                    mail_dom[d]['provider'].append('proofpoint_appliance')
        mail_dom[d]['provider'] = list(set(mail_dom[d]['provider']))

        for tmp_dict in mail_dom[d]['ips']:
            ip = False
            while not ip:
                tmp_name = list(tmp_dict.keys())[0]
                if 'AAAA' in tmp_dict:
                    ip = True
                else:
                    tmp_dict = tmp_dict[tmp_name]
            for rr in tmp_dict:
                for ip in tmp_dict[rr]:
                    mail_dom[d]['hosted_at'].append(tmp_dict[rr][ip]['AS-NAME'])
            mail_dom[d]['hosted_at'] = list(set(mail_dom[d]['hosted_at']))
    return mail_dom


def get_as_data_cymru():
    HOST = "whois.cymru.com"
    PORT = 43
    RDY = "Bulk mode; whois.cymru.com"
    DT = ""

    logger.info('Using Team Cymru Bulk Whois')

    global IP_ADDR_LIST

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            # data = s.recv(1024)
            fs = s.makefile()
            rdy = False
            logger.debug('Sending Begin')
            s.sendall(b"begin\n")
            logger.debug('Waiting for RDY')
            while not rdy:
                line = fs.readline()
                logger.debug('Waiting for RDY, read: %s', line.strip())
                if RDY in line.strip():
                    logger.debug('%s found in string; We are ready!', RDY)
                    rdy = True
            logger.debug('Requesting IPs')
            for ip in IP_ADDR_LIST:
                s.sendall((ip + DT + "\n").encode('utf-8'))
                data_raw = fs.readline().strip()
                logger.debug('read: %s', data_raw)
                try:
                    split_data = data_raw.split('|')
                    try:
                        d = {'ASN': split_data[0].strip(), 'AS-NAME': split_data[2].strip().split()[0]}
                    except Exception as e:
                        logger.warning('request failed with %s', str(e))
                        d = {'ASN': 0, 'AS-NAME': 'No Data Found for IP'}

                    IP_ADDR_LIST[ip]['ASN'] = d['ASN']
                    IP_ADDR_LIST[ip]['AS-NAME'] = d['AS-NAME'].strip(',')
                except (ValueError, KeyError) as ose:
                    sys.exit(f'Error querying Team Cymru Bulk Whois: {ose}')

    except (socket.error, IOError, OSError) as ose:
        sys.exit(f'Error querying Team Cymru Bulk Whois: {ose}')

    # s.sendall(b"end\n")
    # data_raw = ''
    # while  not data_raw == SFX:
    #


def get_as_data():
    the_date = "20221015"
    HOST = "bttf-whois.as59645.net"
    PORT = 10000
    RDY = "# READY"
    SFX = "# goodbye"

    logger.info('Using AS59645 Bulk Whois; Selected date: %s', the_date)

    global IP_ADDR_LIST
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            # data = s.recv(1024)
            fs = s.makefile()
            rdy = False
            while not rdy:
                line = fs.readline()
                if line.strip() == RDY:
                    rdy = True
            s.sendall(b"begin\n")
            for ip in IP_ADDR_LIST:
                s.sendall(f"{ip} {the_date}\n".encode('utf-8'))
            s.sendall(b"end\n")
            data_raw = fs.readline().strip()
            while data_raw and not data_raw == SFX:
                data = json.loads(data_raw)
                if data['results']:
                    d = {'ASN': data['results']['asns'][0], 'AS-NAME': data['results']['as2org'][0]['ASNAME']}
                else:
                    d = {'ASN': 0, 'AS-NAME': 'No Data Found for IP'}
                IP_ADDR_LIST[data['IP']]['ASN'] = d['ASN']
                IP_ADDR_LIST[data['IP']]['AS-NAME'] = d['AS-NAME'].strip(',')
                data_raw = fs.readline().strip()

    except (JSONDecodeError, ValueError, TypeError) as dec:
        logger.exception('Error parsing %s', data_raw)
        sys.exit(f'Error decoding AS59645 Bulk Whois: {dec}')
    except (socket.error, IOError, OSError, JSONDecodeError) as ose:
        sys.exit(f'Error querying AS59645 Bulk Whois: {ose}')


def get_as_data_stub(ip):
    global IP_ADDR_LIST
    d = IP_ADDR_LIST.get(ip)
    if d is None:
        d = {'ASN': 0, 'AS-NAME': 'No Data Found for IP'}
        IP_ADDR_LIST[ip] = d
    return d


def res_to_ip(res, name):
    ret = {}
    ips = []

    name = name.strip('.')
    try:
        r = res.resolve(name, 'CNAME')
        for cn in r:
            ret[name], ips = res_to_ip(res, str(cn.to_text()))
        return ret, ips
    except DNSException as e:
        logger.debug('dns exception quering cname: %s', str(e))
        ret = {name: {'A': {}, 'AAAA': {}}}
        try:
            r = res.resolve(name, 'A')
            for a in r:
                ret[name]['A'][str(a.to_text())] = get_as_data_stub(str(a.to_text()))
                ips.append(str(a.to_text()))
        except DNSException as e:
            logger.debug('dns exception quering A: %s', str(e))

        try:
            r = res.resolve(name, 'AAAA')
            for aaaa in r:
                ret[name]['AAAA'][str(aaaa.to_text())] = get_as_data_stub(str(aaaa.to_text()))
                ips.append(str(aaaa.to_text()))
        except DNSException as e:
            logger.debug('dns exception quering A: %s', str(e))

        return ret, ips


def check_lms_domains(res, lms_dom, u_domains):
    logger.info('Running %s', json.dumps(lms_dom))
    psl = PublicSuffixList()
    for d in lms_dom:
        logger.info('Checking %s %s', str(d), str(u_domains))
        lms_dom[d]['provider'] = []
        lms_dom[d]['hosted_at'] = []
        lms_dom[d]['ips_list'] = []
        tmp_dict, ips = res_to_ip(res, d)
        logger.info('For %s received %s', str(ips), json.dumps(tmp_dict))
        lms_dom[d]['ips_list'] += ips
        lms_dom[d]['ips'].append(tmp_dict)
        in_dom = True
        lms_priv = None
        while in_dom:
            in_dom_tmp = False
            tmp_name = list(tmp_dict.keys())[0]
            logger.info('For %s list is %s', str(tmp_name), str(list(tmp_dict.keys())))
            lms_priv = psl.privatesuffix(tmp_name.strip('.'))
            for u_dom in u_domains:
                if u_dom.strip('.') == lms_priv:
                    in_dom_tmp = True
                # elif 'A' == tmp_name or 'AAAA' == tmp_name:
                #    in_dom_tmp = False
                logger.info('For %s in_tmp set to %s', str(lms_priv), str(in_dom_tmp))
            in_dom = in_dom_tmp
            logger.info('For %s in_dom set to %s', str(tmp_name), str(in_dom))
            if not ('AAAA' in tmp_dict or 'A' in tmp_dict):
                tmp_dict = tmp_dict[tmp_name]
        if lms_priv:
            lms_dom[d]['provider'].append(lms_priv)

        ip = False
        while not ip:
            tmp_name = list(tmp_dict.keys())[0]
            if 'AAAA' in tmp_dict:
                ip = True
            else:
                tmp_dict = tmp_dict[tmp_name]
        for rr in tmp_dict:
            for ip in tmp_dict[rr]:
                lms_dom[d]['hosted_at'].append(tmp_dict[rr][ip]['AS-NAME'])
        lms_dom[d]['hosted_at'] = list(set(lms_dom[d]['hosted_at']))
    logger.info('Returning lms_dom: %s', json.dumps(lms_dom))
    return lms_dom


def set_hosted_at(dom_set):
    global IP_ADDR_LIST
    logger.info('checking dom_set for: %s', json.dumps(dom_set))
    if not dom_set:
        return {}
    for d in dom_set:
        dom_set[d]['hosted_at'] = []
        logger.info('checking %s, %s', str(d), json.dumps(dom_set[d]))
        for h in dom_set[d]['ips']:
            logger.info('checking %s', str(h))
            for fqdn in h:
                logger.info('checking %s, %s', str(fqdn), json.dumps(h[fqdn]))
                tmp_h = h
                while not ('A' in tmp_h or 'AAAA' in tmp_h):
                    fqdn = list(tmp_h.keys())[0]
                    logger.info('checking %s, %s', str(fqdn), json.dumps(tmp_h))
                    tmp_h = tmp_h[fqdn]
                for rr in tmp_h:
                    for ipaddr in tmp_h[rr]:
                        tmp_h[rr][ipaddr] = IP_ADDR_LIST[ipaddr]
                        dom_set[d]['hosted_at'].append(IP_ADDR_LIST[ipaddr]['AS-NAME'])
        dom_set[d]['hosted_at'] = list(set(dom_set[d]['hosted_at']))
    return dom_set


def print_univ_data(univ):
    for u in univ:
        print('###################################')
        print('# ' + univ[u]['name'])
        print('# Domains used: ' + ', '.join(univ[u]['domains']))
        print('#')
        if list(univ[u]['mail_domains'].keys()):
            print('### Email Setup')
            print('# Domains surveyed: ' + ', '.join(list(univ[u]['mail_domains'].keys())))
            print('#')
            for d in univ[u]['mail_domains']:
                print('# Domain: ' + d)
                print('# Provider(s): ' + ', '.join(univ[u]['mail_domains'][d]['provider']))
                print('# Hosted at: ' + ', '.join(univ[u]['mail_domains'][d]['hosted_at']))
                if univ[u]['mail_domains'][d]['comment']:
                    print('# Comment: ' + univ[u]['mail_domains'][d]['comment'])
                if univ[u]['mail_domains'][d]['dmarc']['rua'] and univ[u]['mail_domains'][d]['dmarc']['ruf']:
                    print(
                        '# DMARC reporting: rua=' + ', '.join(univ[u]['mail_domains'][d]['dmarc']['rua']) + '; ruf=' + ', '.join(
                                univ[u]['mail_domains'][d]['dmarc']['ruf']
                                )
                        )
                elif univ[u]['mail_domains'][d]['dmarc']['ruf']:
                    print('# DMARC reporting: ruf=' + ', '.join(univ[u]['mail_domains'][d]['dmarc']['ruf']))
                elif univ[u]['mail_domains'][d]['dmarc']['rua']:
                    print('# DMARC reporting: rua=' + ', '.join(univ[u]['mail_domains'][d]['dmarc']['rua']))
                print('# MXes: ' + ', '.join(univ[u]['mail_domains'][d]['mx']))
                for tmp_dict in univ[u]['mail_domains'][d]['ips']:
                    print('# ')
                    prefix = '# MX: '
                    while 'AAAA' not in tmp_dict:
                        name = list(tmp_dict.keys())[0]
                        print(prefix + name)
                        prefix = '# CNAME -> '
                        tmp_dict = tmp_dict[name]
                    for rr in tmp_dict:
                        for ip in tmp_dict[rr]:
                            print('# ' + rr + ' ' + ip + ' ASN:' + str(tmp_dict[rr][ip]['ASN']) + ' AS-NAME: ' + tmp_dict[rr][ip]['AS-NAME'])
                print('#-')
        if list(univ[u]['lms_domains'].keys()):
            print('### Learning Management System(s)')
            print('# LMS surveyed: ' + ', '.join(list(univ[u]['lms_domains'].keys())))
            print('#')
            for d in univ[u]['lms_domains']:
                print('# LMS Address: https://' + d.strip('.') + '/')
                print('# Provider(s): ' + ', '.join(univ[u]['lms_domains'][d]['provider']))
                print('# Hosted at: ' + ', '.join(univ[u]['lms_domains'][d]['hosted_at']))
                if univ[u]['lms_domains'][d]['comment']:
                    print('# Comment: ' + univ[u]['lms_domains'][d]['comment'])
                print('# ')
                for tmp_dict in univ[u]['lms_domains'][d]['ips']:
                    prefix = '# Base name: '
                    while 'AAAA' not in tmp_dict:
                        name = list(tmp_dict.keys())[0]
                        print(prefix + name)
                        prefix = '# CNAME -> '
                        tmp_dict = tmp_dict[name]
                    for rr in tmp_dict:
                        for ip in tmp_dict[rr]:
                            print('# ' + rr + ' ' + ip + ' ASN:' + str(tmp_dict[rr][ip]['ASN']) + ' AS-NAME: ' + tmp_dict[rr][ip]['AS-NAME'])
                print('#-')
        if list(univ[u]['web_domains'].keys()):
            print('### Base Web Service(s)')
            print('# Names surveyed: ' + ', '.join(list(univ[u]['web_domains'].keys())))
            print('#')
            for d in univ[u]['web_domains']:
                if univ[u]['web_domains'][d]['hosted_at']:
                    print('# FQDN: ' + d.strip('.'))
                    # print('# Provider(s): '+', '.join(univ[u]['web_domains'][d]['provider']))
                    print('# Hosted at: ' + ', '.join(univ[u]['web_domains'][d]['hosted_at']))
                    if univ[u]['web_domains'][d]['comment']:
                        print('# Comment: ' + univ[u]['web_domains'][d]['comment'])
                    print('# ')
                    for tmp_dict in univ[u]['web_domains'][d]['ips']:
                        prefix = '# Base name: '
                        while 'AAAA' not in tmp_dict:
                            name = list(tmp_dict.keys())[0]
                            print(prefix + name)
                            prefix = '# CNAME -> '
                            tmp_dict = tmp_dict[name]
                        for rr in tmp_dict:
                            for ip in tmp_dict[rr]:
                                print('# ' + rr + ' ' + ip + ' ASN:' + str(tmp_dict[rr][ip]['ASN']) + ' AS-NAME: ' + tmp_dict[rr][ip]['AS-NAME'])
                    print('#-')
                else:
                    # print('# '+d+' does not exist')
                    logger.info('web_domain unavailable: %s', json.dumps(univ[u]['web_domains'][d]))
        if list(univ[u]['other_domains'].keys()):
            print('### Other Service(s)')
            print('# Names surveyed: ' + ', '.join(list(univ[u]['other_domains'].keys())))
            print('#')
            for d in univ[u]['other_domains']:
                print('# FQDN: ' + d.strip('.'))
                print('# Provider(s): ' + ', '.join(univ[u]['other_domains'][d]['provider']))
                print('# Hosted at: ' + ', '.join(univ[u]['other_domains'][d]['hosted_at']))
                if univ[u]['other_domains'][d]['comment']:
                    print('# Comment: ' + univ[u]['other_domains'][d]['comment'])
                print('# ')
                for tmp_dict in univ[u]['other_domains'][d]['ips']:
                    prefix = '# Base name: '
                    while 'AAAA' not in tmp_dict:
                        name = list(tmp_dict.keys())[0]
                        print(prefix + name)
                        prefix = '# CNAME -> '
                        tmp_dict = tmp_dict[name]
                    for rr in tmp_dict:
                        for ip in tmp_dict[rr]:
                            print('# ' + rr + ' ' + ip + ' ASN:' + str(tmp_dict[rr][ip]['ASN']) + ' AS-NAME: ' + tmp_dict[rr][ip]['AS-NAME'])
                print('#-')
        if list(univ[u]['vid_domains'].keys()):
            print('### Other Service(s)')
            print('# Domains surveyed: ' + ', '.join(list(univ[u]['vid_domains'].keys())))
            print('#')
            for d in univ[u]['vid_domains']:
                print('# Service Domain: ' + d.strip('.'))
                services = []
                confirmed = {}
                for fqdn in univ[u]['vid_domains'][d]:
                    if len(univ[u]['vid_domains'][d][fqdn]['likelyhood']) > 1 and 'msft' not in univ[u]['vid_domains'][d][fqdn]['provider']:
                        services += univ[u]['vid_domains'][d][fqdn]['provider']
                        logger.info('Found provider %s', str(univ[u]['vid_domains'][d][fqdn]['provider']))
                        confirmed[fqdn] = univ[u]['vid_domains'][d][fqdn]
                    elif 'msft' in univ[u]['vid_domains'][d][fqdn]['provider']:
                        logger.info(json.dumps(univ[u]['vid_domains'][d][fqdn]))
                        if len(univ[u]['vid_domains'][d][fqdn]['likelyhood']) > 1:
                            if 'MICROSOFT' in univ[u]['vid_domains'][d][fqdn]['hosted_at']:
                                services.append('sfb/teams-cloud')
                                univ[u]['vid_domains'][d][fqdn]['provider'] = ['sfb/teams-cloud']
                            else:
                                services.append('sfb/teams-local')
                                univ[u]['vid_domains'][d][fqdn]['provider'] = ['sfb/teams-local']
                            confirmed[fqdn] = univ[u]['vid_domains'][d][fqdn]
                print('# Provider(s): ' + ', '.join(services))
                print('# ')
                for fqdn in confirmed:
                    print('# Service: ' + ', '.join(confirmed[fqdn]['provider']))
                    print('# Hosted at: ' + ', '.join(confirmed[fqdn]['hosted_at']))
                    for tmp_dict in confirmed[fqdn]['ips']:
                        prefix = '# Base name: '
                        while 'AAAA' not in tmp_dict:
                            name = list(tmp_dict.keys())[0]
                            print(prefix + name)
                            prefix = '# CNAME -> '
                            tmp_dict = tmp_dict[name]
                        for rr in tmp_dict:
                            for ip in tmp_dict[rr]:
                                print('# ' + rr + ' ' + ip + ' ASN:' + str(tmp_dict[rr][ip]['ASN']) + ' AS-NAME: ' + tmp_dict[rr][ip]['AS-NAME'])
                    print('#')
                print('#-')
        print('###################################')
        print()


def get_saml_value(text):
    r = re.compile(r'name="SAMLRequest"[^>]+value=.([^\'"]+)')
    a = re.compile(r'form[^<]+action=.([^\'"]+)')
    try:
        r_v = r.findall(text)[0]
        a_v = a.findall(text)[0].replace('&#x2f;', '/').replace('&#x3a;', ':')
        return r_v, a_v
    except UnicodeEncodeError:
        return None, None


def check_vid_domains(res, uni_dom):
    psl = PublicSuffixList()
    ret = {}
    for d in uni_dom:
        # ret[d] = {'hosted_at':[], 'ips':[], "provider":[], 'ips_list': []}
        ret[d] = {}

        test_names_rs = {}
        rem_services = ['.zoom.us.', '.webex.com.']

        priv = psl.privatesuffix(d.strip('.'))
        pref = priv.split('.')[0]
        dot = priv.replace('.', '-')
        live = pref + '-live'

        for s in rem_services:
            sn = s.split('.')[-3]
            if sn not in test_names_rs:
                test_names_rs[sn] = {}

            if len(pref) > 2:
                test_names_rs[sn][pref + s] = d
            test_names_rs[sn][dot + s] = d
            test_names_rs[sn][live + s] = d
        # BBB
        test_names_rs['bbb'] = {}
        for s in ['bbb', 'greenlight', 'scalelite']:
            test_names_rs['bbb'][s + '.' + d] = d

        test_names_rs['msft'] = {'lyncdiscover.' + d: d}
        logger.info('Generated rem_services list for %s: %s', d, json.dumps(test_names_rs))

        logger.info('Getting TXT records for %s', d)
        txt_record = []
        try:
            r = res.resolve(d, 'TXT')
            for txt in r:
                txt_record.append(txt.to_text())
            logger.info('Got TXT record for %s: %s', d, str(txt_record))
        except Exception as e:
            logger.warning('Could not get TXT record for %s: %s', d, str(e))

        # zoom
        for fqdn in test_names_rs['zoom']:
            ip, iplist = res_to_ip(res, fqdn)
            if iplist:
                ret[d][fqdn] = {'hosted_at': [], 'ips': [ip], "provider": ['zoom'], 'ips_list': iplist, 'likelyhood': ['domconfirm']}
                for txtrr in txt_record:
                    if 'ZOOM_verify' in txtrr:
                        ret[d][fqdn]['likelyhood'].append('txtconfirm')
                logger.info('Zoom Host Found: %s', json.dumps(ret[d][fqdn]))

                site_url = "https://" + fqdn + "/signin"
                try:
                    site_support_data_request = requests.get(site_url)
                    site_support_data = site_support_data_request.content.decode('utf-8').strip()

                    if 'SAMLRequest' not in site_support_data:
                        for tmp_d in uni_dom:
                            if tmp_d in site_support_data:
                                ret[d][fqdn]['likelyhood'].append('webconfirm')
                                logger.info('found login reference for %s and domain %s', fqdn, tmp_d)
                        else:
                            logger.info('found no login reference for %s', fqdn)
                    else:
                        v, a = get_saml_value(site_support_data_request.text)
                        # logger.info('SAMLdata: %s', v)
                        logger.info('SAMLaction: %s',  a)
                        req_saml = requests.post(a, data={"SAMLRequest": v})
                        req_saml_res = req_saml.text
                        for tmp_d in uni_dom:
                            if tmp_d in req_saml_res:
                                ret[d][fqdn]['likelyhood'].append('webconfirm')
                                logger.info('found login reference for %s and domain %s', fqdn, tmp_d)

                except Exception as e:
                    logger.warning('Failed to get login data from %s: %s', site_url, str(e))
            # print_debug('INFO: WebEx Host Found: '+json.dumps(ret[d][fqdn]))

        # webex
        for fqdn in test_names_rs['webex']:
            ip, iplist = res_to_ip(res, fqdn)
            if iplist:
                ret[d][fqdn] = {'hosted_at': [], 'ips': [ip], "provider": ['webex'], 'ips_list': iplist, 'likelyhood': ['domconfirm']}
                # https://tue.webex.com/webappng/api/v1/brand4Support?siteurl=tue
                site_name = fqdn.split('.')[0]
                site_url = "https://" + fqdn + "/webappng/api/v1/brand4Support?siteurl=" + site_name
                try:
                    site_support_data = requests.get(site_url).content.decode('utf-8').strip()
                    # print_debug('INFO: '+site_support_data)
                    for tmp_d in uni_dom:
                        if tmp_d in site_support_data:
                            ret[d][fqdn]['likelyhood'].append('webconfirm')
                            logger.info('found support reference for %s and domain %s', fqdn, tmp_d)
                    else:
                        logger.info('found no support reference for %s', fqdn)
                except Exception as e:
                    logger.warning('Failed to get support data from %s: %s', site_url, str(e))
                logger.info('WebEx Host Found: %s', json.dumps(ret[d][fqdn]))

        # bbb
        for fqdn in test_names_rs['bbb']:
            ip, iplist = res_to_ip(res, fqdn)
            if iplist:
                ret[d][fqdn] = {'hosted_at': [], 'ips': [ip], "provider": ['bbb'], 'ips_list': iplist, 'likelyhood': ['domconfirm']}
                site_url = "https://" + fqdn + "/"
                try:
                    site_support_data = requests.get(site_url).content.decode('utf-8').strip()
                    # print_debug('INFO: '+site_support_data)
                    if 'BigBlueButton' in site_support_data:
                        ret[d][fqdn]['likelyhood'].append('webconfirm')
                        logger.info('found support reference for %s', fqdn)
                    else:
                        logger.info('found no support reference for %s', fqdn)
                except Exception as e:
                    logger.warning('Failed to get support data from %s: %s', site_url, str(e))
                logger.info('BBB Host Found: %s', json.dumps(ret[d][fqdn]))

        # SfB
        for fqdn in test_names_rs['msft']:
            ip, iplist = res_to_ip(res, fqdn)
            if iplist:
                ret[d][fqdn] = {'hosted_at': [], 'ips': [ip], "provider": ['msft'], 'ips_list': iplist, 'likelyhood': ['domconfirm']}
                for txtrr in txt_record:
                    if 'MS=ms' in txtrr:
                        ret[d][fqdn]['likelyhood'].append('txtconfirm')
                logger.info('Msft Host Found: %s', json.dumps(ret[d][fqdn]))
    return ret


def main():

    args = parse_args()

    base_domain = args.domain
    whois = args.whois
    vid_check = args.vid_check
    web_check = args.web_check
    cache_file = args.cache_file

    resolver = get_resolver(args.dns_resolver)

    if args.add_domains:
        add_domains = [item for sublist in args.add_domains for item in sublist]
    else:
        add_domains = []
    if args.mail_domains:
        mail_domains = [item for sublist in args.mail_domains for item in sublist]
    else:
        mail_domains = []
    if args.lms_domains:
        lms_domains = [item for sublist in args.lms_domains for item in sublist]
    else:
        lms_domains = []
    if args.other_domains:
        other_domains = [item for sublist in args.other_domains for item in sublist]
    else:
        other_domains = []

    universities = {}
    logger.info('Generating universities dictionary')
    universities[base_domain] = {
        'name': base_domain, 'domains': [base_domain], 'mail_domains': {}, 'lms_domains': {},
        'other_domains': {}, 'web_domains': {}, 'vid_domains': {}
        }
    for ad in add_domains:
        universities[base_domain]['domains'].append(ad)
    for md in mail_domains:
        universities[base_domain]['mail_domains'][md] = {'hosted_at': '', 'mx': [], 'comment': ''}
    for ld in lms_domains:
        universities[base_domain]['lms_domains'][ld] = {'hosted_at': '', 'ips': [], 'comment': ''}
    for od in other_domains:
        universities[base_domain]['other_domains'][od] = {'hosted_at': '', 'ips': [], 'comment': ''}
    for wd in universities[base_domain]['domains']:
        universities[base_domain]['web_domains'][wd] = {'hosted_at': '', 'ips': [], 'comment': ''}
        universities[base_domain]['web_domains']['www.' + wd] = {'hosted_at': '', 'ips': [], 'comment': ''}
    for vd in universities[base_domain]['domains']:
        universities[base_domain]['vid_domains'][vd] = {'hosted_at': '', 'ips': [], 'comment': ''}

    logger.info('Generated university dictionary: %s', json.dumps(universities))

    use_cache = False
    if cache_file:
        if os.path.isfile(cache_file):
            use_cache = True
            logger.info('%s found; Using cache.', cache_file)
    if use_cache:
        universities = json.loads(open('./data.json').read().strip())
    else:
        logger.info('no cache found; Querying data.')
        for u in universities:
            universities[u]['mail_domains'] = check_mail_domains(resolver, universities[u]['mail_domains'])
            universities[u]['lms_domains'] = check_lms_domains(resolver, universities[u]['lms_domains'], universities[u]['domains'])
            universities[u]['other_domains'] = check_lms_domains(resolver, universities[u]['other_domains'], universities[u]['domains'])
            if not web_check:
                universities[u]['web_domains'] = check_lms_domains(resolver, universities[u]['web_domains'], universities[u]['domains'])
            else:
                universities[u]['web_domains'] = {}
            if not vid_check:
                universities[u]['vid_domains'] = check_vid_domains(resolver, universities[u]['domains'])
            else:
                universities[u]['vid_domains'] = {}
        if whois == 'cymru':
            get_as_data_cymru()
        else:
            get_as_data()
        for u in universities:
            universities[u]['mail_domains'] = set_hosted_at(universities[u]['mail_domains'])
            universities[u]['lms_domains'] = set_hosted_at(universities[u]['lms_domains'])
            universities[u]['other_domains'] = set_hosted_at(universities[u]['other_domains'])
            if not web_check:
                universities[u]['web_domains'] = set_hosted_at(universities[u]['web_domains'])
            if not vid_check:
                for vdom in universities[u]['vid_domains']:
                    universities[u]['vid_domains'][vdom] = set_hosted_at(universities[u]['vid_domains'][vdom])
        if cache_file:
            of = open(cache_file, 'w+')
            of.write(json.dumps(universities) + '\n')
            of.close()
    print_univ_data(universities)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
