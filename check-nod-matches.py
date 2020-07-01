import requests
import base64
import json
import re
import math
import logging
import time
import gzip
import ipaddress
import urllib
import ssl
import agate
import dns.resolver
import domain

#########################################################			
logging.basicConfig(handlers = [logging.FileHandler('check-node-match.log'), logging.StreamHandler()],level=logging.DEBUG,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

nod_logs = 'security-activity_security-events.csv'
tide_apikey = ''
use_already_downloaded_IOC_files = True

#########################################################

def is_fqdn(hostname):
    """
    :param hostname: string
    :return: bool
    """
    #  Remove trailing dot
    try:  # Is this necessary?
        if hostname[-1] == '.':
            hostname = hostname[0:-1]
    except IndexError:
        return False

    #  Check total length of hostname < 253
    if len(hostname) > 253:
        return False

    #  Split hostname into list of DNS labels
    hostname = hostname.split('.')

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = re.compile(r'^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

    #  Check if length of each DNS label < 63
    #  Match DNS label to pattern
    for label in hostname:
        if len(label) > 63:
            return False
        if not fqdn.match(label):
            return False

    #  Found no errors, returning True
    return True
    
#########################################################

def getNODDomains(nod_logs):
    data ={}
    nod_csv = agate.Table.from_csv(nod_logs)
    for row in nod_csv.rows:
        IOC = {}
        hostname = row['Query']
        if hostname [-1] == '.':
            hostname = hostname[0:-1]
        
        if not data.get(hostname):
            logging.debug('Adding domain {}'.format(hostname))
            IOC['item']=hostname
            data[hostname] = IOC
        
        l2domain = re.search('([^\.]+\.[^\.]+)$', hostname, re.IGNORECASE)
        if l2domain:
            IOC = {}
            hostname = l2domain.group(1)
            if not data.get(hostname):
                logging.debug('Adding l2 domain {}'.format(hostname))
                IOC['item']=hostname
                data[hostname] = IOC
    
    for hostname in list(data):
    	try:
            rr=dns.resolver.query(hostname, 'A')
            for liaddr in rr.response.answer[0].items:
                IOC = {}
                IOC['item'] = liaddr.address
                IOC['ip']   = liaddr.address
                IOC['host'] = hostname
                data[liaddr.address] = IOC
                if not data[hostname].get('ip'):
                	 data[hostname]['ip']=[]
                data[hostname]['ip'].append(liaddr.address)
                logging.debug('Resolving {}, IP {}'.format(hostname, liaddr.address))
    	except:
    	    pass

    logging.info('Read ok, FarSight Newly Observed Domains IOCs: {}'.format(len(data)))
    
    return data
    
#########################################################			

def getTIDEIOCs(test_mode, ioctype, url,tide_apikey):
	data ={}
	filename = './tide_'+ ioctype + '.json'
	
	if not test_mode:
		method='GET'
		auth = base64.encodebytes(('%s:%s' % (tide_apikey,' ')).encode()).decode().replace('\n', '').strip()
		
		ssl._create_default_https_context = ssl._create_unverified_context
		
		opener = urllib.request.build_opener()
		opener.addheaders = opener.addheaders = [('Authorization', 'Basic %s' % auth ), ('Content-Type','application/x-www-form-urlencoded') ,('User-agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36')]
		urllib.request.install_opener(opener)
		urllib.request.urlretrieve(url, filename)

	file= open(filename, 'r')
	
	for line in file:
		try:
			r_json=json.loads(line)
		except:
			raise Exception('Unable to load into a json format')

		if r_json['type'] == 'HOST':
			data[r_json['host']]				= {}
			data[r_json['host']]['item'] 		= r_json['host']
			data[r_json['host']]['host'] 		= r_json['host']
			data[r_json['host']]['description'] = r_json['property']
		elif r_json['type'] == 'IP':
			data[r_json['ip']]					= {}
			data[r_json['ip']]['item'] 		    = r_json['ip']
			data[r_json['ip']]['ip'] 		    = r_json['ip']
			data[r_json['ip']]['description']   = r_json['property']
		
	file.close()
	
	logging.info('Download ok, {} TIDE IOCs: {}'.format(ioctype,len(data)))
	return data

#########################################################			

def generate_new_IOC_list(TIDE_IOCs,input_IOCs,IOC_list_name):
	data ={}
	diff = set(input_IOCs).intersection(set(TIDE_IOCs))
	for k in diff:
		if not TIDE_IOCs[k].get('description') == "Policy_NewlyObservedDomains":
			data[k] = {**TIDE_IOCs[k], **input_IOCs[k]}
	
	logging.info('IOC overlapping is {}%'.format(int(100*len(data)/len(input_IOCs))))
	logging.info('IOCs in {} matches : {}'.format(IOC_list_name,len(input_IOCs)))
	logging.info('IOCs in TIDE: {}'.format(len(TIDE_IOCs)))
	logging.info('IOCs in {} matches and in TIDE: {}'.format(IOC_list_name,len(data)))
	
	return data

#########################################################			

hosts_url = 'https://api.activetrust.net/api/data/threats/state/host?data_format=ndjson'
ips_url   = 'https://api.activetrust.net/api/data/threats/state/IP?data_format=ndjson'

TIDE = {}
TIDE.update(getTIDEIOCs(use_already_downloaded_IOC_files, 'host', hosts_url, tide_apikey))
TIDE.update(getTIDEIOCs(use_already_downloaded_IOC_files, 'ip', ips_url, tide_apikey))

NOD_domains= getNODDomains(nod_logs)

NOD_now_bad= generate_new_IOC_list(TIDE, NOD_domains,"Farsight Newly Observed Domains")
logging.info('{:<50}  {:<50}  {:<50}'.format('-- Description --','-- host --', '-- ip --'))
[logging.info('{:<50}  {:<50}  {:<50}'.format(NOD_now_bad[x].get('description','') ,NOD_now_bad[x].get('host',''), str(NOD_now_bad[x].get('ip',''))))  for x in set(NOD_now_bad)]
