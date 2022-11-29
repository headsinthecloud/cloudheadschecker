# Intro
This small tool allows you to check key-aspects of a university's infrastructure for cloud hosting.
See *Usage* for a detailed usage. Example invocation:
```
cloudheadschecker example.com -d example-university.edu -m students.example.com faculty.example.com example.com -l canvas.example.com -o hr-service.example.com --cache-file example-university-data.json
```
This queries for a university using `example.com` as domain name, as well as `example-university.edu`.
Email services run on `students.example.com`, `faculty.example.com`, and `example.com`.
The LMS is at `canvas.example.com`.
Additionally, `hr-service.example.com` should be checked for cloud hosting.
Finally, all data should be written to `example-university-data.json`.

# Installation

You can install cloudheadschecker in the following ways:

First, you should clone the repository:
```
git clone [...]
```

## Manual
To manually install cloudheadschecker, run:
```
cd repository_path/
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## pip
Usign `pip`, after checking out the repository, you should run:
```
cd repository_path/
./make_dist.sh
pip install dist/cloudheadschecker-0.0.1.tar.gz
```

## Docker
To run cloudheadschecker using docker, run:

# Usage
```
$ cloudheadschecker -h
usage: cloudheadschecker [-h] [--dns-resolver DNS_RESOLVER] [--whois WHOIS]
                         [--debug] [-d ADD_DOMAINS [ADD_DOMAINS ...]]
                         [-m MAIL_DOMAINS [MAIL_DOMAINS ...]]
                         [-l LMS_DOMAINS [LMS_DOMAINS ...]]
                         [-o OTHER_DOMAINS [OTHER_DOMAINS ...]] [-z] [-w]
                         [--cache-file CACHE_FILE]
                         domain

positional arguments:
  domain                Base domain of the university, e.g.: example.com;
                        Required argument.

optional arguments:
  -h, --help            show this help message and exit
  --dns-resolver DNS_RESOLVER
                        Explicit DNS resolver to use, defaults to system
                        resolver. e.g.: 141.1.1.1
  --whois WHOIS         Bulk-Whois service to use. Possible options are
                        'cymru' and 'as59645'. Defaults to 'as59645'.
  --debug               Print verbose output for debugging.
  -d ADD_DOMAINS [ADD_DOMAINS ...]
                        Additinal domains of the university; Can receive
                        multiple arguments, e.g.: example.ac.com example.net
  -m MAIL_DOMAINS [MAIL_DOMAINS ...]
                        Mail domains of the university; Can receive multiple
                        arguments, e.g.: example.com
  -l LMS_DOMAINS [LMS_DOMAINS ...]
                        LMS names of the university; Can receive multiple
                        arguments, e.g.: canvas.example.com
  -o OTHER_DOMAINS [OTHER_DOMAINS ...]
                        Other names of the university; Can receive multiple
                        arguments, e.g.: survey.cs.example.com
  -z                    Disable check for usage of Video-Chat solutions (Zoom,
                        WebEx, BBB, etc.)
  -w                    Disable check base-domain/www. website hosting.
  --cache-file CACHE_FILE
                        Write full data to this file.
```

# Example invocation:
```
$ cloudheadschecker stanford.edu -l canvas.stanford.edu -m cs.stanford.edu stanford.edu -o gradadmissions.stanford.edu 
# Getting mail data for cs.stanford.edu
# Getting mail data for stanford.edu
###################################
# stanford.edu
# Domains used: stanford.edu
#
### Email Setup
# Domains surveyed: cs.stanford.edu, stanford.edu
#
# Domain: cs.stanford.edu
# Provider(s): 
# Hosted at: STANFORD
# MXes: smtp2.cs.stanford.edu., smtp1.cs.stanford.edu., cs.stanford.edu., smtp3.cs.stanford.edu.
# 
# MX: smtp2.cs.stanford.edu
# A 171.64.64.26 ASN:32 AS-NAME: STANFORD
# 
# MX: smtp1.cs.stanford.edu
# A 171.64.64.25 ASN:32 AS-NAME: STANFORD
# 
# MX: cs.stanford.edu
# A 171.64.64.64 ASN:32 AS-NAME: STANFORD
# 
# MX: smtp3.cs.stanford.edu
# A 171.64.64.27 ASN:32 AS-NAME: STANFORD
#-
# Domain: stanford.edu
# Provider(s): proofpoint_appliance
# Hosted at: PROOFPOINT-ASN-US-WEST
# DMARC reporting: rua=dmarc_ruf@emaildefense.proofpoint.com; ruf=dmarc_ruf@emaildefense.proofpoint.com
# MXes: mxa-00000d03.gslb.pphosted.com., mxb-00000d03.gslb.pphosted.com.
# 
# MX: mxa-00000d03.gslb.pphosted.com
# A 148.163.149.244 ASN:26211 AS-NAME: PROOFPOINT-ASN-US-WEST
# 
# MX: mxb-00000d03.gslb.pphosted.com
# A 148.163.149.244 ASN:26211 AS-NAME: PROOFPOINT-ASN-US-WEST
#-
### Learning Management System(s)
# LMS surveyed: canvas.stanford.edu
#
# LMS Address: https://canvas.stanford.edu/
# Provider(s): instructure.com
# Hosted at: AMAZON-AES
# 
# Base name: canvas.stanford.edu
# CNAME -> stanford2-vanity.instructure.com
# CNAME -> canvas-iad-prod-c98-1329570919.us-east-1.elb.amazonaws.com
# A 3.221.184.254 ASN:14618 AS-NAME: AMAZON-AES
# A 3.228.83.160 ASN:14618 AS-NAME: AMAZON-AES
# A 54.89.42.10 ASN:14618 AS-NAME: AMAZON-AES
#-
### Base Web Service(s)
# Names surveyed: stanford.edu, www.stanford.edu
#
# FQDN: stanford.edu
# Hosted at: STANFORD
# 
# Base name: stanford.edu
# A 171.67.215.200 ASN:32 AS-NAME: STANFORD
# AAAA 2607:f6d0:0:925a::ab43:d7c8 ASN:32 AS-NAME: STANFORD
#-
# FQDN: www.stanford.edu
# Hosted at: FASTLY
# 
# Base name: www.stanford.edu
# CNAME -> pantheon-systems.map.fastly.net
# A 151.101.114.133 ASN:54113 AS-NAME: FASTLY
# AAAA 2a04:4e42:1b::645 ASN:54113 AS-NAME: FASTLY
#-
### Other Service(s)
# Names surveyed: gradadmissions.stanford.edu
#
# FQDN: gradadmissions.stanford.edu
# Provider(s): acsitefactory.com
# Hosted at: AMAZON-02
# 
# Base name: gradadmissions.stanford.edu
# CNAME -> gradadmissionsd9.cardinalsites.acsitefactory.com
# CNAME -> cardinalsites01live.enterprise-g1.acquia-sites.com
# A 34.215.171.12 ASN:16509 AS-NAME: AMAZON-02
#-
### Other Service(s)
# Domains surveyed: stanford.edu
#
# Service Domain: stanford.edu
# Provider(s): zoom, webex
# 
# Service: zoom
# Hosted at: CLOUDFLARESPECTRUM
# Base name: stanford.zoom.us
# CNAME -> www.zoom.us
# CNAME -> zoom.us
# A 170.114.52.2 ASN:209242 AS-NAME: CLOUDFLARESPECTRUM
#
# Service: webex
# Hosted at: 13445
# Base name: stanford.webex.com
# CNAME -> nebulaie.webex.com
# CNAME -> global-nebulaie.webex.com
# A 66.114.168.199 ASN:13445 AS-NAME: 13445
#
#-
###################################
```
