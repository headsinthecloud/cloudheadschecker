# Intro
For the historic perspective from our paper "Heads in the Clouds? Measuring Universities’ Migration to Public Clouds: Implications for Privacy & Academic Freedom", we used a large passive dataset. 
As this passive dataset cannot be publicly shared, we implemented a small script that gathers the data we are looking at actively, i.e., 'as of now'.
Please note that this means that differences to the last state of our passive dataset (October 2022) may occur.
Furthermore, you need to have a-priori knowledge of:
1. All domains used by a university
2. Domains used for email by a university (the part behind the `@`)
3. The domain used for the learning management system (like `canvas.example.com` or `brightspace.example.com`)

See *Usage* for a detailed usage. Example invocation:
```
cloudheadschecker example.com -d example-university.edu -m students.example.com faculty.example.com example.com -l canvas.example.com -o hr-service.example.com --cache-file example-university-data.json
```
This queries for a university using `example.com` as domain name, as well as `example-university.edu`.
Email services run on `students.example.com`, `faculty.example.com`, and `example.com`.
The LMS is at `canvas.example.com`.
Additionally, `hr-service.example.com` should be checked for cloud hosting.
Finally, all data should be written to `example-university-data.json`.

# University Data
You can find an overview of university domains here: https://git.aperture-labs.org/Cloudheads/universities

# Installation

You can install cloudheadschecker manually, with pip, or you can run it in Docker (pre-built and self-built images):

First, you should clone the repository:
```
git clone https://git.aperture-labs.org/Cloudheads/cloudheadschecker
```

## Using pypi
You can install this package from pypi. Simply run:
```
pip install cloudheadschecker
```
This will instal the tool and all dependencies; Thereafter you will have `cloudheadschecker` in your `PATH` and can simply run it.

## Using pip

You can choose to use the source dist in the Docker/pkg directory or build the python package yourself.

To build a fresh python package from the repository, after cloning the repository run:

```
cd cloudheadschecker/
./make_dist.sh
```

You will now find a source and binary distribution in the subdirectory dist/

Alternatively you can use the source distribution we provide in the Docker/pkg directory for convinience.

We recommend installing the python package either in a virtual environment or a users home.

### Virtual Environment

A new virtual environment containing the tool is created with these steps:

```
cd cloudheadschecker/
./make_dist.sh
python -m venv venv
source venv/bin/activate
pip install dist/cloudheadschecker-0.0.4.tar.gz
```

### Installation in users home

Alternatively the tool and its wrapper script can be installed in a users home as follows:

```
cd cloudheadschecker/
./make_dist.sh
pip install --user dist/cloudheadschecker-0.0.4.tar.gz
```
again, the file Docker/pkg/cloudheadschecker-0.0.4.tar.gz can be used alternatively


## Docker (pre-built image)

To run cloudheadschecker using docker, run:
```
cd cloudheadschecker/Docker/
docker load -i  cloudheadschecker.tgz
docker run -it --rm cloudheadschecker cloudheadschecker [ARGUMENTS]
```

Omitting the start command will drop you to a shell inside the container, where the command cloudheadschecker is available.

## Docker (self-built image)

You can choose to recreate the python package as well, or skip this step and the build script will use a provided file from the repository.
```
cd cloudheadschecker/
./make_dist.sh
cp dist/cloudheadschecker-0.0.4.tar.gz Docker/pkg/
```

To run cloudheadschecker using docker and a self-built image, then run:

```
cd Docker/
./build.sh
docker run -it --rm cloudheadschecker cloudheadschecker [ARGUMENTS]
```

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
# Getting mail data for tudelft.nl
# Getting mail data for student.tudelft.nl
###################################
# tudelft.nl
# Domains used: tudelft.nl
#
### Email Setup
# Domains surveyed: tudelft.nl, student.tudelft.nl
#
# Domain: tudelft.nl
# Provider(s): proofpoint_appliance
# Hosted at: TUDELFT-NL
# DMARC reporting: rua=dmarc_ruf@emaildefense.proofpoint.com; ruf=dmarc_ruf@emaildefense.proofpoint.com
# MXes: ppa1.tudelft.nl., ppa4.tudelft.nl., ppa3.tudelft.nl., ppa2.tudelft.nl.
# 
# MX: ppa1.tudelft.nl
# A 131.180.77.181 ASN:1128 AS-NAME: TUDELFT-NL
# 
# MX: ppa4.tudelft.nl
# A 131.180.77.184 ASN:1128 AS-NAME: TUDELFT-NL
# 
# MX: ppa3.tudelft.nl
# A 131.180.77.183 ASN:1128 AS-NAME: TUDELFT-NL
# 
# MX: ppa2.tudelft.nl
# A 131.180.77.182 ASN:1128 AS-NAME: TUDELFT-NL
#-
# Domain: student.tudelft.nl
# Provider(s): surf
# Hosted at: SURFNET-NL
# MXes: mx11.surfmailfilter.nl., mx10.surfmailfilter.nl.
# 
# MX: mx11.surfmailfilter.nl
# A 195.169.13.8 ASN:1103 AS-NAME: SURFNET-NL
# AAAA 2001:610:1:40ab:195:169:13:8 ASN:1103 AS-NAME: SURFNET-NL
# 
# MX: mx10.surfmailfilter.nl
# A 192.87.106.168 ASN:1103 AS-NAME: SURFNET-NL
# AAAA 2001:610:188:173:192:87:106:168 ASN:1103 AS-NAME: SURFNET-NL
#-
### Learning Management System(s)
# LMS surveyed: brightspace.tudelft.nl
#
# LMS Address: https://brightspace.tudelft.nl/
# Provider(s): brightspace.com
# Hosted at: AMAZON-02
# 
# Base name: brightspace.tudelft.nl
# CNAME -> tudelft.brightspace.com
# A 54.220.17.170 ASN:16509 AS-NAME: AMAZON-02
# A 54.77.244.65 ASN:16509 AS-NAME: AMAZON-02
# A 54.194.179.95 ASN:16509 AS-NAME: AMAZON-02
# A 52.211.110.116 ASN:16509 AS-NAME: AMAZON-02
#-
### Base Web Service(s)
# Names surveyed: tudelft.nl, www.tudelft.nl
#
# FQDN: tudelft.nl
# Hosted at: TUDELFT-NL, SURFNET-NL
# 
# Base name: tudelft.nl
# A 130.161.128.82 ASN:1128 AS-NAME: TUDELFT-NL
# AAAA 2001:610:908:112:131:180:77:102 ASN:1103 AS-NAME: SURFNET-NL
#-
# FQDN: www.tudelft.nl
# Hosted at: AMAZON-02
# 
# Base name: www.tudelft.nl
# A 3.251.22.13 ASN:16509 AS-NAME: AMAZON-02
# A 54.73.174.150 ASN:16509 AS-NAME: AMAZON-02
#-
### Other Service(s)
# Domains surveyed: tudelft.nl
#
# Service Domain: tudelft.nl
# Provider(s): zoom, sfb/teams-local
# 
# Service: zoom
# Hosted at: CLOUDFLARESPECTRUM
# Base name: tudelft.zoom.us
# CNAME -> www.zoom.us
# CNAME -> zoom.us
# A 170.114.52.2 ASN:209242 AS-NAME: CLOUDFLARESPECTRUM
#
# Service: sfb/teams-local
# Hosted at: TUDELFT-NL
# Base name: lyncdiscover.tudelft.nl
# A 131.180.187.62 ASN:1128 AS-NAME: TUDELFT-NL
#
#-
###################################
```
