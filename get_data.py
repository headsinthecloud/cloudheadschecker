#!/usr/bin/env python3

import sys
import os

import dns.resolver
import socket
import json
import argparse
import requests
import re

from publicsuffixlist import PublicSuffixList
psl = PublicSuffixList()

res = None
DEBUG = False
IP_ADDR_LIST = {}

# Debug printing
def print_debug(s):
	if DEBUG:
		print(str(s))


def parse_args():
	global DEBUG
	# Parsing arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('domain', help='Base domain of the university, e.g.: example.com; Required argument.')
	parser.add_argument('--dns-resolver', help="Explicit DNS resolver to use, defaults to system resolver. e.g.: 141.1.1.1", dest='dns_resolver')
	parser.add_argument('--whois', help="Bulk-Whois service to use. Possible options are 'cymru' and 'as59645'. Defaults to 'as59645'.", dest='whois')
	parser.add_argument('--debug', help="Print verbose output for debugging.", dest='debug', action="store_true")
	parser.add_argument(
		'-d', help='Additinal domains of the university; Can receive multiple arguments, e.g.: example.ac.com example.net', dest='add_domains', action='append',
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
	DEBUG = args.debug

	print_debug('INFO: Parsing arguments:')
	print_debug('INFO: ' + str(args))
	return args


def get_resolver(dns_resolver):

	# Configure specific resolver if it is configured
	if not dns_resolver:
		print_debug('INFO: No nameserver given. Using system resolver.')
		# Setting up default resolver
		the_resolver = dns.resolver.Resolver(configure=True)
	else:
		print_debug('INFO: Setting resolver to: ' + str(dns_resolver))
		try:
			the_resolver = dns.resolver.Resolver(configure=False)
			the_resolver.nameservers = [dns_resolver]
		except:
			sys.exit('ERROR: Could not set resolver ' + str(dns_resolver))

	# Test resolver
	try:
		if dns_resolver:
			print_debug('INFO: Testing resolver: ' + dns_resolver)
		else:
			print_debug('INFO: Testing system resolver')
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
				print_debug('INFO: Found all ' + str(len(res_servers)) + ' root-servers at: ' + dns_resolver)
			else:
				print_debug('INFO: Found all ' + str(len(res_servers)) + ' root-servers at the system resolver.')
		else:
			if dns_resolver:
				print('ERROR: Found only ' + str(len(res_servers)) + '/' + str(len(root_servers)) + ' root-servers at: ' + dns_resolver)
			else:
				print('ERROR: Found only ' + str(len(res_servers)) + '/' + str(len(root_servers)) + ' root-servers at the system resolver.')
			print('ERROR: Please use another resolver; Exiting.')
	except Exception as e:
		print('ERROR: Resolver test failed with ' + str(e))
		sys.exit(2)

	return the_resolver




def check_mail_domains(mail_dom):
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
		except:
			pass
		try:
			r = res.query('_dmarc.'+d, 'TXT')
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
		except:
			pass
		for mx in mail_dom[d]['mx']:
			ipdata, ips = res_to_ip(mx)
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
	SFX = ""
	DT = ""

	print_debug('INFO: Using Team Cymru Bulk Whois')

	global IP_ADDR_LIST
	res_data = {}
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((HOST, PORT))
		#data = s.recv(1024)
		fs = s.makefile()
		rdy = False
		print_debug('INFO: Sending Begin')
		s.sendall(b"begin\n")
		print_debug('INFO: Waiting for RDY')
		while not rdy:
			l = fs.readline()
			print_debug('INFO: Waiting for RDY, read: '+l.strip())
			if RDY in l.strip():
				print_debug('INFO: '+RDY+' found in string; We are ready!')
				rdy = True
		print_debug('INFO: Requesting IPs')
		for ip in IP_ADDR_LIST:
			s.sendall((ip+DT+"\n").encode('utf-8'))
			data_raw = fs.readline().strip()
			print_debug('INFO: read: '+data_raw)
			try:
				split_data = data_raw.split('|')
				try:
					d = {'ASN': split_data[0].strip(), 'AS-NAME':split_data[2].strip().split()[0]}
				except Exception as e:
					print_debug('WARNING: request failed with '+str(e))
					d = {'ASN':0 , 'AS-NAME':'No Data Found for IP'}

				IP_ADDR_LIST[ip]['ASN'] = d['ASN']
				IP_ADDR_LIST[ip]['AS-NAME'] = d['AS-NAME'].strip(',')
			except:
				pass

		# s.sendall(b"end\n")
		# data_raw = ''
		# while  not data_raw == SFX:
		#


def get_as_data():
	HOST = "bttf-whois.as59645.net"
	PORT = 10000
	RDY = "# READY"
	SFX = "# goodbye"
	DT = " 20221015"

	print_debug('INFO: Using AS59645 Bulk Whois; Selected date:'+DT)

	global IP_ADDR_LIST
	res_data = {}
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((HOST, PORT))
		#data = s.recv(1024)
		fs = s.makefile()
		rdy = False
		while not rdy:
			l = fs.readline()
			if l.strip() == RDY:
				rdy = True
		s.sendall(b"begin\n")
		for ip in IP_ADDR_LIST:
			s.sendall((ip+DT+"\n").encode('utf-8'))
		s.sendall(b"end\n")
		data_raw = ''
		while  not data_raw == SFX:
			data_raw = fs.readline().strip()
			try:
				data = json.loads(data_raw)
				d = {}
				if data['results']:
					d = {'ASN':data['results']['asns'][0] , 'AS-NAME':data['results']['as2org'][0]['ASNAME']}
				else:
					d = {'ASN':0 , 'AS-NAME':'No Data Found for IP'}
				IP_ADDR_LIST[data['IP']]['ASN'] = d['ASN']
				IP_ADDR_LIST[data['IP']]['AS-NAME'] = d['AS-NAME'].strip(',')
			except:
				pass


def store_ip_dict(ip, d):
	global IP_ADDR_LIST
	IP_ADDR_LIST[ip] = d


def get_as_data_stub(ip):
	d = {'ASN': 0 , 'AS-NAME': 'No Data Found for IP'}
	store_ip_dict(ip, d)
	return d


def res_to_ip(name):
	ret = {}
	name = name.strip('.')
	try:
		r = res.resolve(name, 'CNAME')
		for cn in r:
			ret[name], ips = res_to_ip(str(cn.to_text()))
		return ret, ips
	except Exception as e:
		ret = {name: {'A':{}, 'AAAA':{}}}
		ips = []
		try:
			r = res.resolve(name, 'A')
			for a in r:
				ret[name]['A'][str(a.to_text())] = get_as_data_stub(str(a.to_text()))
				ips.append(str(a.to_text()))
		except Exception as e:
			pass
		try:
			r = res.resolve(name, 'AAAA')
			for aaaa in r:
				ret[name]['AAAA'][str(aaaa.to_text())] = get_as_data_stub(str(aaaa.to_text()))
				ips.append(str(aaaa.to_text()))
		except Exception as e:
			pass
		return ret, ips


def check_lms_domains(lms_dom, u_domains):
	print_debug('INFO: Running '+json.dumps(lms_dom))
	for d in lms_dom:
		print_debug('INFO: Checking '+str(d)+' '+str(u_domains))
		lms_dom[d]['provider'] = []
		lms_dom[d]['hosted_at'] = []
		lms_dom[d]['ips_list'] = []
		tmp_dict, ips = res_to_ip(d)
		print_debug('INFO: For '+str(ips)+' received '+json.dumps(tmp_dict))
		lms_dom[d]['ips_list'] += ips
		lms_dom[d]['ips'].append(tmp_dict)
		p = 'none'
		in_dom = True
		while in_dom:
			in_dom_tmp = False
			tmp_name = list(tmp_dict.keys())[0]
			print_debug('INFO: For '+str(tmp_name)+' list is '+str(list(tmp_dict.keys())))
			lms_priv = psl.privatesuffix(tmp_name.strip('.'))
			for u_dom in u_domains:
				if u_dom.strip('.') == lms_priv:
					in_dom_tmp = True
				#elif 'A' == tmp_name or 'AAAA' == tmp_name:
				#	in_dom_tmp = False
				print_debug('INFO: For '+str(lms_priv)+' in_tmp set to '+str(in_dom_tmp))
			in_dom = in_dom_tmp
			print_debug('INFO: For '+str(tmp_name)+' in_dom set to '+str(in_dom))
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
	print_debug('INFO: Returning lms_dom: '+json.dumps(lms_dom))
	return lms_dom


def set_hosted_at(dom_set):
	global IP_ADDR_LIST
	print_debug('INFO: checking dom_set for: '+json.dumps(dom_set))
	if not dom_set:
		return {}
	for d in dom_set:
		dom_set[d]['hosted_at'] = []
		print_debug('INFO: checking '+str(d)+', '+json.dumps(dom_set[d]))
		for h in dom_set[d]['ips']:
			print_debug('INFO: checking '+str(h))
			for fqdn in h:
				print_debug('INFO: checking '+str(fqdn)+', '+json.dumps(h[fqdn]))
				tmp_h = h
				while not ('A' in tmp_h or 'AAAA' in tmp_h):
					fqdn = list(tmp_h.keys())[0]
					print_debug('INFO: checking '+str(fqdn)+', '+json.dumps(tmp_h))
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
		print('# '+univ[u]['name'])
		print('# Domains used: '+', '.join(univ[u]['domains']))
		print('#')
		if list(univ[u]['mail_domains'].keys()):
			print('### Email Setup')
			print('# Domains surveyed: '+', '.join(list(univ[u]['mail_domains'].keys())))
			print('#')
			for d in univ[u]['mail_domains']:
				print('# Domain: '+d)
				print('# Provider(s): '+', '.join(univ[u]['mail_domains'][d]['provider']))
				print('# Hosted at: '+', '.join(univ[u]['mail_domains'][d]['hosted_at']))
				if univ[u]['mail_domains'][d]['comment']:
					print('# Comment: '+univ[u]['mail_domains'][d]['comment'])
				if univ[u]['mail_domains'][d]['dmarc']['rua'] and univ[u]['mail_domains'][d]['dmarc']['ruf']:
					print('# DMARC reporting: rua='+', '.join(univ[u]['mail_domains'][d]['dmarc']['rua'])+'; ruf='+', '.join(univ[u]['mail_domains'][d]['dmarc']['ruf']))
				elif univ[u]['mail_domains'][d]['dmarc']['ruf']:
					print('# DMARC reporting: ruf='+', '.join(univ[u]['mail_domains'][d]['dmarc']['ruf']))
				elif univ[u]['mail_domains'][d]['dmarc']['rua']:
					print('# DMARC reporting: rua='+', '.join(univ[u]['mail_domains'][d]['dmarc']['rua']))
				print('# MXes: '+', '.join(univ[u]['mail_domains'][d]['mx']))
				for tmp_dict in univ[u]['mail_domains'][d]['ips']:
					print('# ')
					name = ''
					prefix = '# MX: '
					while not 'AAAA' in tmp_dict:
						name = list(tmp_dict.keys())[0]
						print(prefix+name)
						prefix = '# CNAME -> '
						tmp_dict = tmp_dict[name]
					for rr in tmp_dict:
						for ip in tmp_dict[rr]:
							print('# '+rr+' '+ip+' ASN:'+str(tmp_dict[rr][ip]['ASN'])+' AS-NAME: '+tmp_dict[rr][ip]['AS-NAME'])
				print('#-')
		if list(univ[u]['lms_domains'].keys()):
			print('### Learning Management System(s)')
			print('# LMS surveyed: '+', '.join(list(univ[u]['lms_domains'].keys())))
			print('#')
			for d in univ[u]['lms_domains']:
				print('# LMS Address: https://'+d.strip('.')+'/')
				print('# Provider(s): '+', '.join(univ[u]['lms_domains'][d]['provider']))
				print('# Hosted at: '+', '.join(univ[u]['lms_domains'][d]['hosted_at']))
				if univ[u]['lms_domains'][d]['comment']:
					print('# Comment: '+univ[u]['lms_domains'][d]['comment'])
				print('# ')
				for tmp_dict in univ[u]['lms_domains'][d]['ips']:
					name = ''
					prefix = '# Base name: '
					while not 'AAAA' in tmp_dict:
						name = list(tmp_dict.keys())[0]
						print(prefix+name)
						prefix = '# CNAME -> '
						tmp_dict = tmp_dict[name]
					for rr in tmp_dict:
						for ip in tmp_dict[rr]:
							print('# '+rr+' '+ip+' ASN:'+str(tmp_dict[rr][ip]['ASN'])+' AS-NAME: '+tmp_dict[rr][ip]['AS-NAME'])
				print('#-')
		if list(univ[u]['web_domains'].keys()):
			print('### Base Web Service(s)')
			print('# Names surveyed: '+', '.join(list(univ[u]['web_domains'].keys())))
			print('#')
			for d in univ[u]['web_domains']:
				if univ[u]['web_domains'][d]['hosted_at']:
					print('# FQDN: '+d.strip('.'))
					#print('# Provider(s): '+', '.join(univ[u]['web_domains'][d]['provider']))
					print('# Hosted at: '+', '.join(univ[u]['web_domains'][d]['hosted_at']))
					if univ[u]['web_domains'][d]['comment']:
						print('# Comment: '+univ[u]['web_domains'][d]['comment'])
					print('# ')
					for tmp_dict in univ[u]['web_domains'][d]['ips']:
						name = ''
						prefix = '# Base name: '
						while not 'AAAA' in tmp_dict:
							name = list(tmp_dict.keys())[0]
							print(prefix+name)
							prefix = '# CNAME -> '
							tmp_dict = tmp_dict[name]
						for rr in tmp_dict:
							for ip in tmp_dict[rr]:
								print('# '+rr+' '+ip+' ASN:'+str(tmp_dict[rr][ip]['ASN'])+' AS-NAME: '+tmp_dict[rr][ip]['AS-NAME'])
					print('#-')
				else:
					#print('# '+d+' does not exist')
					print_debug('INFO: web_domain unavailable: '+json.dumps(univ[u]['web_domains'][d]))
		if list(univ[u]['other_domains'].keys()):
			print('### Other Service(s)')
			print('# Names surveyed: '+', '.join(list(univ[u]['other_domains'].keys())))
			print('#')
			for d in univ[u]['other_domains']:
				print('# FQDN: '+d.strip('.'))
				print('# Provider(s): '+', '.join(univ[u]['other_domains'][d]['provider']))
				print('# Hosted at: '+', '.join(univ[u]['other_domains'][d]['hosted_at']))
				if univ[u]['other_domains'][d]['comment']:
					print('# Comment: '+univ[u]['other_domains'][d]['comment'])
				print('# ')
				for tmp_dict in univ[u]['other_domains'][d]['ips']:
					name = ''
					prefix = '# Base name: '
					while 'AAAA' not in tmp_dict:
						name = list(tmp_dict.keys())[0]
						print(prefix+name)
						prefix = '# CNAME -> '
						tmp_dict = tmp_dict[name]
					for rr in tmp_dict:
						for ip in tmp_dict[rr]:
							print('# '+rr+' '+ip+' ASN:'+str(tmp_dict[rr][ip]['ASN'])+' AS-NAME: '+tmp_dict[rr][ip]['AS-NAME'])
				print('#-')
		if list(univ[u]['vid_domains'].keys()):
			print('### Other Service(s)')
			print('# Domains surveyed: '+', '.join(list(univ[u]['vid_domains'].keys())))
			print('#')
			for d in univ[u]['vid_domains']:
				print('# Service Domain: '+d.strip('.'))
				services = []
				confirmed = {}
				for fqdn in univ[u]['vid_domains'][d]:
					if len(univ[u]['vid_domains'][d][fqdn]['likelyhood']) > 1 and not 'msft' in univ[u]['vid_domains'][d][fqdn]['provider']:
						services += univ[u]['vid_domains'][d][fqdn]['provider']
						print_debug('INFO: Found provider '+str(univ[u]['vid_domains'][d][fqdn]['provider']))
						confirmed[fqdn] = univ[u]['vid_domains'][d][fqdn]
					elif 'msft' in univ[u]['vid_domains'][d][fqdn]['provider']:
						print_debug('INFO: '+json.dumps(univ[u]['vid_domains'][d][fqdn]))
						if len(univ[u]['vid_domains'][d][fqdn]['likelyhood']) > 1:
							if 'MICROSOFT' in univ[u]['vid_domains'][d][fqdn]['hosted_at']:
								services.append('sfb/teams-cloud')
								univ[u]['vid_domains'][d][fqdn]['provider'] = ['sfb/teams-cloud']
							else:
								services.append('sfb/teams-local')
								univ[u]['vid_domains'][d][fqdn]['provider'] = ['sfb/teams-local']
							confirmed[fqdn] = univ[u]['vid_domains'][d][fqdn]
				print('# Provider(s): '+', '.join(services))
				print('# ')
				for fqdn in confirmed:
					print('# Service: '+', '.join(confirmed[fqdn]['provider']))
					print('# Hosted at: '+', '.join(confirmed[fqdn]['hosted_at']))
					for tmp_dict in confirmed[fqdn]['ips']:
						name = ''
						prefix = '# Base name: '
						while 'AAAA' not in tmp_dict:
							name = list(tmp_dict.keys())[0]
							print(prefix+name)
							prefix = '# CNAME -> '
							tmp_dict = tmp_dict[name]
						for rr in tmp_dict:
							for ip in tmp_dict[rr]:
								print('# '+rr+' '+ip+' ASN:'+str(tmp_dict[rr][ip]['ASN'])+' AS-NAME: '+tmp_dict[rr][ip]['AS-NAME'])
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
	except (ET.ParseError, UnicodeEncodeError):
		return None, None


def check_vid_domains(uni_dom):
	ret = {}
	for d in uni_dom:
		#ret[d] = {'hosted_at':[], 'ips':[], "provider":[], 'ips_list': []}
		ret[d] = {}

		test_names_rs = {}
		rem_services = ['.zoom.us.', '.webex.com.']

		priv = psl.privatesuffix(d.strip('.'))
		pref = priv.split('.')[0]
		dot = priv.replace('.','-')
		live = pref+'-live'

		for s in rem_services:
			sn = s.split('.')[-3]
			if not sn in test_names_rs:
				test_names_rs[sn] = {}

			if len(pref) > 2:
				test_names_rs[sn][pref+s] = d
			test_names_rs[sn][dot+s] = d
			test_names_rs[sn][live+s] = d
		# BBB
		test_names_rs['bbb'] = {}
		for s in ['bbb', 'greenlight', 'scalelite']:
			test_names_rs['bbb'][s+'.'+d] = d

		test_names_rs['msft'] = {'lyncdiscover.'+d: d}
		print_debug('INFO: Generated rem_services list for '+d+': '+json.dumps(test_names_rs))

		print_debug('INFO: Getting TXT records for '+d)
		txt_record = []
		try:
			r = res.resolve(d, 'TXT')
			for txt in r:
				txt_record.append(txt.to_text())
			print_debug('INFO: Got TXT record for '+d+': '+str(txt_record))
		except Exception as e:
			print_debug('WARNING: Could not get TXT record for '+d+': '+str(e))

		# zoom
		for fqdn in test_names_rs['zoom']:
			ip, iplist = res_to_ip(fqdn)
			if iplist:
				ret[d][fqdn] = {'hosted_at':[], 'ips':[ip], "provider":['zoom'], 'ips_list': iplist, 'likelyhood':['domconfirm']}
				for txtrr in txt_record:
					if 'ZOOM_verify' in txtrr:
						ret[d][fqdn]['likelyhood'].append('txtconfirm')
				print_debug('INFO: Zoom Host Found: '+json.dumps(ret[d][fqdn]))

				site_name = fqdn.split('.')[0]
				site_url = "https://"+fqdn+"/signin"
				try:
					site_support_data_request = requests.get(site_url)
					site_support_data = site_support_data_request.content.decode('utf-8').strip()

					if not 'SAMLRequest' in site_support_data:
						for tmp_d in uni_dom:
							if tmp_d in site_support_data:
								ret[d][fqdn]['likelyhood'].append('webconfirm')
								print_debug('INFO: found login reference for '+fqdn+' and domain '+tmp_d)
						else:
							print_debug('INFO: found no login reference for '+fqdn)
					else:
						v, a = get_saml_value(site_support_data_request.text)
						#print_debug('INFO: SAMLdata: '+v)
						print_debug('INFO: SAMLaction: '+a)
						req_saml = requests.post(a, data = {"SAMLRequest": v})
						req_saml_res = req_saml.text
						for tmp_d in uni_dom:
							if tmp_d in req_saml_res:
								ret[d][fqdn]['likelyhood'].append('webconfirm')
								print_debug('INFO: found login reference for '+fqdn+' and domain '+tmp_d)

				except Exception as e:
					print_debug('WARNING: Failed to get login data from '+site_url+': '+str(e))
				# print_debug('INFO: WebEx Host Found: '+json.dumps(ret[d][fqdn]))

		# webex
		for fqdn in test_names_rs['webex']:
			ip, iplist = res_to_ip(fqdn)
			if iplist:
				ret[d][fqdn] = {'hosted_at':[], 'ips':[ip], "provider":['webex'], 'ips_list': iplist, 'likelyhood':['domconfirm']}
				# https://tue.webex.com/webappng/api/v1/brand4Support?siteurl=tue
				site_name = fqdn.split('.')[0]
				site_url = "https://"+fqdn+"/webappng/api/v1/brand4Support?siteurl="+site_name
				try:
					site_support_data = requests.get(site_url).content.decode('utf-8').strip()
					#print_debug('INFO: '+site_support_data)
					for tmp_d in uni_dom:
						if tmp_d in site_support_data:
							ret[d][fqdn]['likelyhood'].append('webconfirm')
							print_debug('INFO: found support reference for '+fqdn+' and domain '+tmp_d)
					else:
						print_debug('INFO: found no support reference for '+fqdn)
				except Exception as e:
					print_debug('WARNING: Failed to get support data from '+site_url+': '+str(e))
				print_debug('INFO: WebEx Host Found: '+json.dumps(ret[d][fqdn]))

		# bbb
		for fqdn in test_names_rs['bbb']:
			ip, iplist = res_to_ip(fqdn)
			if iplist:
				ret[d][fqdn] = {'hosted_at':[], 'ips':[ip], "provider":['bbb'], 'ips_list': iplist, 'likelyhood':['domconfirm']}
				site_name = fqdn.split('.')[0]
				site_url = "https://"+fqdn+"/"
				try:
					site_support_data = requests.get(site_url).content.decode('utf-8').strip()
					#print_debug('INFO: '+site_support_data)
					if 'BigBlueButton' in site_support_data:
						ret[d][fqdn]['likelyhood'].append('webconfirm')
						print_debug('INFO: found support reference for '+fqdn+' and domain '+tmp_d)
					else:
						print_debug('INFO: found no support reference for '+fqdn)
				except Exception as e:
					print_debug('WARNING: Failed to get support data from '+site_url+': '+str(e))
				print_debug('INFO: BBB Host Found: '+json.dumps(ret[d][fqdn]))

		# SfB
		for fqdn in test_names_rs['msft']:
			ip, iplist = res_to_ip(fqdn)
			if iplist:
				ret[d][fqdn] = {'hosted_at':[], 'ips':[ip], "provider":['msft'], 'ips_list': iplist, 'likelyhood':['domconfirm']}
				for txtrr in txt_record:
					if 'MS=ms' in txtrr:
						ret[d][fqdn]['likelyhood'].append('txtconfirm')
				print_debug('INFO: Msft Host Found: '+json.dumps(ret[d][fqdn]))
	return ret


def main():
	global res

	args = parse_args()

	base_domain = args.domain
	whois = args.whois
	vid_check = args.vid_check
	web_check = args.web_check
	cache_file = args.cache_file
	dns_resolver = args.dns_resolver

	res = get_resolver(dns_resolver)

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
	print_debug('INFO: Generating universities dictionary')
	universities[base_domain] = {'name': base_domain, 'domains': [base_domain], 'mail_domains': {}, 'lms_domains': {},
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

	print_debug('INFO: Generated university dictionary: ' + json.dumps(universities))

	use_cache = False
	if cache_file:
		if os.path.isfile(cache_file):
			use_cache = True
			print_debug('INFO: ' + cache_file + ' found; Using cache.')
	if use_cache:
		universities = json.loads(open('./data.json').read().strip())
	else:
		print_debug('INFO: no cache found; Querying data.')
		for u in universities:
			universities[u]['mail_domains'] = check_mail_domains(universities[u]['mail_domains'])
			universities[u]['lms_domains'] = check_lms_domains(universities[u]['lms_domains'], universities[u]['domains'])
			universities[u]['other_domains'] = check_lms_domains(universities[u]['other_domains'], universities[u]['domains'])
			if not web_check:
				universities[u]['web_domains'] = check_lms_domains(universities[u]['web_domains'], universities[u]['domains'])
			else:
				universities[u]['web_domains'] = {}
			if not vid_check:
				universities[u]['vid_domains'] = check_vid_domains(universities[u]['domains'])
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
