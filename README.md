# Intro
This small tool allows you to check key-aspects of a university's infrastructure for cloud hosting.
See *Usage* for a detailed usage. Example invocation:
```
./get_data.py example.com -d example-university.edu -m students.example.com faculty.example.com example.com -l canvas.example.com -o hr-service.example.com --cache-file example-university-data.json
```
This queries for a university using `example.com` as domain name, as well as `example-university.edu`.
Email services run on `students.example.com`, `faculty.example.com`, and `example.com`.
The LMS is at `canvas.example.com`.
Additionally, `hr-service.example.com` should be checked for cloud hosting.
Finally, all data should be written to `example-university-data.json`.

# Usage
```
usage: get_data.py [-h] [--dns-resolver DNS_RESOLVER] [--whois WHOIS] [--debug] [-d ADD_DOMAINS [ADD_DOMAINS ...]] [-m MAIL_DOMAINS [MAIL_DOMAINS ...]] [-l LMS_DOMAINS [LMS_DOMAINS ...]] [-o OTHER_DOMAINS [OTHER_DOMAINS ...]] [-z] [-w] [--cache-file CACHE_FILE] domain

positional arguments:
  domain                Base domain of the university, e.g.: example.com; Required argument.

optional arguments:
  -h, --help            show this help message and exit
  --dns-resolver DNS_RESOLVER
                        Explicit DNS resolver to use, defaults to system resolver. e.g.: 141.1.1.1
  --whois WHOIS         Bulk-Whois service to use. Possible options are 'cymru' and 'as59645'. Defaults to 'as59645'.
  --debug               Print verbose output for debugging.
  -d ADD_DOMAINS [ADD_DOMAINS ...]
                        Additinal domains of the university; Can receive multiple arguments, e.g.: example.ac.com example.net
  -m MAIL_DOMAINS [MAIL_DOMAINS ...]
                        Mail domains of the university; Can receive multiple arguments, e.g.: example.com
  -l LMS_DOMAINS [LMS_DOMAINS ...]
                        LMS names of the university; Can receive multiple arguments, e.g.: canvas.example.com
  -o OTHER_DOMAINS [OTHER_DOMAINS ...]
                        Other names of the university; Can receive multiple arguments, e.g.: survey.cs.example.com
  -z                    Disable check for usage of Video-Chat solutions (Zoom, WebEx, BBB, etc.)
  -w                    Disable check base-domain/www. website hosting.
  --cache-file CACHE_FILE
                        Write full data to this file.
```
