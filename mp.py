#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ohal@softserevinc.com
#
"""
MSG parser
: param: input filename MSG
: return: output to file, example -
ostas@softservecom.com         From
ober@softservecom.com          To
http://www.google.com          Body
---
Total e-mail addresses 2
Total URLs          1
"""
# import modules
import optparse
import os
import sys
import email
import re
import logging
import logging.handlers
import ConfigParser
import json
import pickle
# constants
RE_EMAIL = '[\w\.=-]+@(?:[\w-]+\.)+\w{2,4}'
#RE_EMAIL = '[\w\.=-]+@([a-z0-9-]+)(\.)([a-z]{2,4})(\.?)([a-z]{0,4})'
#RE_EMAIL = '[\w\.=-]+@[\w\.-]+\.[\w]{2,3}'
RE_URL = 'https?:\/\/[^ \n\r]+'
#(?=[\s\.,$])' <- look-ahead
# defaults
log_parser = logging.getLogger(__name__)
#functions
def email_addr_count(inp):
    """
    find emails in string cancelling duplicates
    : param inp: string to search email addresses (string)
    : return: whole email addresses (list of string)

    >>> email_addr_count("email@example.com")
    ['email@example.com']

    >>> email_addr_count("ohalenok@softserve.info")
    ['ohalenok@softserve.info']

    >>> email_addr_count("o_halenok@softserve.info")
    ['o_halenok@softserve.info']

    >>> email_addr_count("email@com")
    []

    >>> email_addr_count("email@example..com")
    []

    >>> email_addr_count("email@example.com email@example.com email@example.com")
    ['email@example.com', 'email@example.com', 'email@example.com']

    >>> email_addr_count("1@example.com 2@example.com 3@example.com")
    ['1@example.com', '2@example.com', '3@example.com']

    >>> email_addr_count("From: TopCoder Competitions Team <no-reply@topcoder.com>")
    ['no-reply@topcoder.com']

    >>> email_addr_count("- The TopCoder(R) Competitions leron3@prykladna.lviv.ua leron2@prykladna.lviv.ua leron1@prykladna.lviv.ua Team")
    ['leron1@prykladna.lviv.ua', 'leron2@prykladna.lviv.ua', 'leron3@prykladna.lviv.ua']

    >>> email_addr_count("@example.com")
    []

    >>> email_addr_count("email@.com")
    []

    """
    return sorted(list(re.findall(RE_EMAIL, inp)))
def url_addr_count(inp):
    """
    find urls in string cancelling duplicates
    : param inp: string to search urls (string)
    : return: whole urls (list of string)

    >>> url_addr_count('https://plus.google.com/104268008777050019973')
    ['https://plus.google.com/104268008777050019973']

    >>> url_addr_count('https://plus.google.com/104268008777050019973 https://plus.google.com/104268008777050019973')
    ['https://plus.google.com/104268008777050019973', 'https://plus.google.com/104268008777050019973']

    >>> url_addr_count('https://plus.google.com/104268008777050019973 https://plus.google.com/')
    ['https://plus.google.com/', 'https://plus.google.com/104268008777050019973']

    >>> url_addr_count('You Tweet? So do we! Follow TopCoder on Twitter for conversations on innovation, design and development.  http://twitter.com/topcoder')
    ['http://twitter.com/topcoder']

    >>> url_addr_count('You Tweet? http://twitter.com/topcoder So do we! Follow TopCoder on Twitter for conversations on innovation, design and development.')
    ['http://twitter.com/topcoder']

    >>> url_addr_count('htps://plus.google.com/104268008777050019973')
    []

    >>> url_addr_count('http:/plus.google.com')
    []

    """
    return sorted(list(re.findall(RE_URL, inp)))
def lst_from_dct(dct):
    """
    parsing dictionary, count emails and urls in fields without duplicates and log
    : param dct: input dictionary (dict)
    : return email_list, url_list: output lists of emails and urls (list, list)
    """
# create lists of all emails&urls depends on dictionary content
    email_list = []
    url_list = []
    for k in ("from", "to", "cc", "bcc", "bodyemails"):
        if dct.get(k):
            email_list.extend(dct[k])
    if dct.get("bodyurls"):
        url_list = list(dct['bodyurls'])
# save all results to mp.rpt
#    with open("mp.rpt", "w") as file_to_out:
#        for k in ("from", "to", "cc", "bcc", "bodyemails", "bodyurls"):
#            if dct.get(k):
#                for value in dct[k]:
#                    file_to_out.write("%s " % value + "%s" % k.upper() + "\n")
#        file_to_out.write("---" + "\n")
#        file_to_out.write("Total e-mail addresses %s" % \
#                          len(set(email_list)) + "\n")
#        file_to_out.write("Total URLs %s" % \
#                         len(set(url_list)) + "\n")
# log results
    for k in ("from", "to", "cc", "bcc", "bodyemails", "bodyurls"):
        if dct.get(k):
            for value in dct[k]:
                log_parser.debug("%s " % value + "%s" % k.upper())
    log_parser.debug("---")
    log_parser.debug("Total e-mail addresses %s" % \
                     len(set(email_list)))
    log_parser.debug("Total URLs %s" % \
                     len(set(url_list)))
    return (email_list, url_list)
def json_from_dct(dct, email_list, url_list):
    """
    parsing dictionary, list of emails and urls and create dictionary as JSON
    : param dct: input dictionary (dict)
    : param email_list: list of emails (list)
    : param url_list: list of urls (list)
    : return json_dct: dictionary as JSON (dict)
    """
# create dictionary as JSON
    json_dct = {}
    for email_key in set(email_list):
        json_entry = {}
        for key in ("from", "to", "cc", "bcc", "bodyemails"):
            if dct.get(key) and dct[key].count(email_key) > 0:
                json_entry[key] = dct[key].count(email_key)
        json_dct[email_key] = json_entry
    for url_key in set(url_list):
        if dct.get("bodyurls") and dct["bodyurls"].count(url_key) > 0:
            json_dct[url_key] = dct["bodyurls"].count(url_key)
    return json_dct
def json_dct_merge(j_curr, j_prev):
    """
    parsing dictionary, list of emails and urls and create dictionary as JSON
    : param j_curr: current/new dictionary as JSON (dict)
    : param j_prev: previous/old dictionary as JSON (dict)
    : return j_upda: dictionary as JSON (dict)
    """
# updating old dictionary from file
    for key in j_curr.keys():
# check if url
        if ':' in key:
# update old url counter by new value
            j_prev[key] = j_prev.get(key, 0) + j_curr[key]
# check if new url
            if key not in j_prev.keys():
# update dictionary by new url
                j_prev[key] = j_curr[key]
# if not url = email
        else:
# check if old email
            if key in j_prev.keys():
# for old email with old values
                for key_email in j_curr[key].keys():
# update old email by new values
                    j_prev[key][key_email] = j_prev[key].get(key_email, 0) \
                                             + j_curr[key][key_email]
# update dictionary by new email
            else:
                j_prev[key] = j_curr[key]
    return j_prev
def msg_from_file(file_name, o_file, o_format):
    """
    parsing file as MSG, find emails and urls in fields and log
    : param file_name: input filename/folder (string)
    : param o_file: output filename (string)
    : param o_format: output format: 'JSON' | 'PKL"
    """
# checking MSG content and creating dictionary
    dct = {}
    with open(file_name, 'r') as file_to_read:
# parsing file as MSG
        message = email.message_from_file(file_to_read)
# if MSG from file does not have fields FROM&TO then it does not valid MSG
        if (not message.get("from")) and (not message.get("to")):
            log_parser.error("MSG is not a valid email message")
            return
# try to get FROM field
        if message.get("from"):
# create dictionary entry as list of valid emails
            dct["from"] = email_addr_count(message["from"])
# warning if it does not have valid emails
            if len(dct.get("from", [])) == 0:
                log_parser.warning("MSG does not have valid email"
                                   " address *FROM*")
# warning if it does not have field FROM
        else:
            log_parser.warning("MSG does not contain field *FROM*")
# try to get TO field
        if message.get("to"):
# create dictionary entry as list of valid emails
            dct["to"] = email_addr_count(message["to"])
# warning if it does not have valid emails
            if len(dct.get("to", [])) == 0:
                log_parser.warning("MSG does not have valid email"
                                   " address *TO*")
# warning if it does not have field TO
        else:
            log_parser.warning("MSG does not contain field *TO*")
# try to get CC field and create dictionary entry
        if message.get("cc"):
            dct["cc"] = email_addr_count(message["cc"])
# try to get BCC field and create dictionary entry
        if message.get("bcc"):
            dct["bcc"] = email_addr_count(message["bcc"])
# try to get BODY of message
        if len(message.get_payload()) > 0:
            body = message.get_payload()
# parsing BODY for valid emails&urls and create dictionary entries
            dct["bodyemails"] = email_addr_count(body)
            dct["bodyurls"] = url_addr_count(body)
# warning if it does not have valid emails&urls
            if len(dct.get("bodyemails",
                           [])) == 0 and len(dct.get("bodyurls",
                           [])) == 0:
                log_parser.warning("MSG does not contain any"
                            " url or email address in *BODY*")
# warning if it does not have field BODY
        else:
            log_parser.warning("MSG does not contain field *BODY*")
# create lists of emails&urls from current dictionary
    email_list, url_list = lst_from_dct(dct)
# create current/new dictionary as JSON
    j_c = json_from_dct(dct, email_list, url_list)
#    print "dict -", dct
#    print "emails -", len(email_list), "-", email_list
#    print "urls -", url_list
# output file create/update/is corrupt
    try:
# try to read file as string
        with open(o_file, "r") as file_out:
# load data from file
            load_data = file_out.read()
# try to read as JSON
        j_i = json.loads(load_data)
        log_parser.debug("updating JSON input file...")
# update current/new JSON dictionary from file
        j_c = json_dct_merge(j_c, j_i)
    except IOError:
# warning if file does not exist
        log_parser.debug("output file does not exist...")
    except:
        try:
# try to read as PKL
            j_i = pickle.loads(load_data)
            log_parser.debug("updating PKL input file...")
# update current/new JSON dictionary from file
            j_c = json_dct_merge(j_c, j_i)
        except:
# warning if file is not JSON/PKL or corrupt
            log_parser.debug("output file is not JSON/PKL or corrupt...")
# current dictionary to file as JSON/PKL
    if o_format == "JSON":
        log_parser.debug("create JSON file...")
        to_file = json.dumps(j_c)
    elif o_format == "PKL":
        log_parser.debug("create PKL file...")
        to_file = pickle.dumps(j_c)
# write data to file
    with open(o_file, "w") as file_out:
            file_out.write(to_file)
def main():
    """
    main module
    """
# defaults
    usage = "usage: %prog [options] -f FILENAME"
# parsing the CLI string for options and arguments
    mailparser = optparse.OptionParser(usage,
                epilog = "MSG parser - "
                "parse MSG file for valid emails&urls, "
                "save result and log")
    mailparser.add_option("-f", "--file", dest="filename",
                          help="read data from FILENAME")
    mailparser.add_option("-c", "--config", dest="cfg",
                          help="read from CONFIGFILE")
    mailparser.add_option("-o", "--output", dest="output", default="mp.out",
                          help="save data to OUTPUTFILENAME")
    mailparser.add_option("-t", "--type", dest="savetype", default="JSON",
                          help="output file type JSON or PKL [default - JSON]")
    mailparser.add_option("-l", "--logfile", dest="logfile", default="console",
                          help="log to LOGFILENAME [default console]")
    mailparser.add_option("-v", "--verbose", dest="verbose", default="0",
                          help="verbosity level [default 0 - silent]")
    try:
        (options, args) = mailparser.parse_args()
# set options from INI file if exist, all options will be overriden
        config = ConfigParser.SafeConfigParser({"filename": options.filename,
                                                "output": options.output,
                                                "type": options.savetype,
                                                "logfile": options.logfile,
                                                "verbose": options.verbose})
# if config INI is set just read actual options from INI
        if options.cfg:
            config.read(options.cfg)
            options.filename = config.get("msg","filename")
            options.output =  config.get("msg","output")
            options.savetype = config.get("msg","type")
            options.logfile = config.get("msg","logfile")
            options.verbose = config.get("msg","verbose")
# logging depends on console, syslog or file output
        formatter = logging.Formatter("%(asctime)s %(levelname)s:%(filename)s:"
                                      "%(module)s.%(funcName)s:"
                                      "%(lineno)d - %(message)s",
                                      "%d/%m/%Y %H:%M:%S")
# if console output then handler is sys.stderr
        if options.logfile == "console":
            hdlr = logging.StreamHandler(sys.stderr)
# if syslog output then handler is /dev/syslog
        elif options.logfile == "syslog":
            formatter = logging.Formatter("%(levelname)s:%(filename)s:"
                                          "%(module)s.%(funcName)s:"
                                          "%(lineno)d - %(message)s")
            hdlr = logging.handlers.SysLogHandler(address="/dev/log")
# if file output then handler is file
        else:
            hdlr = logging.FileHandler(options.logfile)
        hdlr.setFormatter(formatter)
        log_parser.addHandler(hdlr)
# checking file type JSON/pickle
        if options.savetype not in ("JSON", "PKL"):
            log_parser.error("file type must be JSON or PKL...")
            sys.exit(0)
# logging depends on verbosity level
        if options.verbose == "0":
            log_parser.setLevel(logging.CRITICAL)
        elif options.verbose == "1":
            log_parser.setLevel(logging.ERROR)
        elif options.verbose == "2":
            log_parser.setLevel(logging.INFO)
        elif options.verbose == "3":
            log_parser.setLevel(logging.DEBUG)
        else:
            log_parser.error("verbose level must be 0, 1, 2 or 3...")
            sys.exit(0)
# parse directory/file
        if options.filename:
# if directory
            if os.path.isdir(options.filename):
# for files in directory only
                for file_name in os.listdir(options.filename):
# only if file, it does not parse directory in directory
                    if os.path.isfile(file_name):
# call the function for each file
                        msg_from_file(os.path.join(options.filename, file_name),
                                      options.output,
                                      options.savetype)
# call the function for particular file
            elif os.path.isfile(options.filename):
                msg_from_file(options.filename,
                              options.output,
                              options.savetype)
            else:
                log_parser.error("file does not exist...")
                sys.exit(0)
# input file must be set
        else:
            mailparser.print_help()
            log_parser.error("FILENAME must be set...")
            sys.exit(0)
# if something wrong in general get exception info for debugging
    except Exception:
        log_parser.error("general exception...")
        log_parser.error(sys.exc_info())
        sys.exit(0)
if __name__ == "__main__":
#    import doctest
#    doctest.testmod()
    main()
