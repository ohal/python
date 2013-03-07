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
import hashlib


# constants
RE_EMAIL = "[\w\.=-]+@(?:[\w-]+\.)+[a-z]{2,4}"
#RE_EMAIL = '[\w\.=-]+@([a-z0-9-]+)(\.)([a-z]{2,4})(\.?)([a-z]{0,4})'
#RE_EMAIL = '[\w\.=-]+@[\w\.-]+\.[\w]{2,3}'
RE_URL = "https?:\/\/[^ \n\r\"<>]+"
#[^\"<>]+"
#(?=[\s\.,$])' <- look-ahead


# defaults
LOG_PARSER = logging.getLogger(__name__)


# global dictionary of hashes
hash_dct = {}


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
# create lists of all emails&urls depending on dictionary content
    email_list = []
    url_list = []
# collect the emails and extend the list of emails
    for k in ("from", "to", "cc", "bcc", "bodyemails"):
        if dct.get(k):
# log emails parsing
            LOG_PARSER.debug("%s " % ", ".join(set(dct[k])) +
                             "%s" % k.upper())
# add each email to list
            email_list.extend(dct[k])
# collect the urls and create the list of urls
    if dct.get("bodyurls"):
# log urls parsing
        LOG_PARSER.debug("%s " % ", ".join(set(dct["bodyurls"])) +
                         "%s" % "bodyurls".upper())
# create the list of urls
        url_list = list(dct["bodyurls"])
# log the statistic
    LOG_PARSER.debug("---")
    LOG_PARSER.debug("Total e-mail addresses %s" % \
                     len(set(email_list)))
    LOG_PARSER.debug("Total URLs %s" % \
                     len(set(url_list)))
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
    return (email_list, url_list)


def email_url_dct(dct, email_list, url_list):
    """
    parsing dictionary, list of emails and urls and create dictionary
    of emails&urls without duplicates and counts it in each field
    : param dct: input dictionary (dict)
    : param email_list: list of emails (list)
    : param url_list: list of urls (list)
    : return e_u_dct: dictionary of emails&urls (dict)
    """
# create dictionary of emails&urls
    e_u_dct = {}
# create entries for emails without duplicates
    for email_key in set(email_list):
        d_entry = {}
# count entries in all fields
        for key in ("from", "to", "cc", "bcc", "bodyemails"):
# create entry of each field if it exist
            if dct.get(key) and dct[key].count(email_key) > 0:
                d_entry[key] = dct[key].count(email_key)
# save it in dectionary
        e_u_dct[email_key] = d_entry
# create entries for urls without duplicates
    for url_key in set(url_list):
        e_u_dct[url_key] = dct["bodyurls"].count(url_key)
    return e_u_dct


def set_log_stream(log_dir):
    """
    set the direction/handler of logging - console, syslog or file name
    : param log_dir: direction console|syslog|file name (string)
    """
# logging depends on console, syslog or file output
    formatter = logging.Formatter("%(asctime)s %(levelname)s:%(filename)s:"
                                  "%(module)s.%(funcName)s:"
                                  "%(lineno)d - %(message)s",
                                  "%d/%m/%Y %H:%M:%S")
# if console output then handler is sys.stderr
    if log_dir == "console":
        hdlr = logging.StreamHandler(sys.stderr)
# if syslog output then handler is /dev/syslog
    elif log_dir == "syslog":
        formatter = logging.Formatter("%(levelname)s:%(filename)s:"
                                      "%(module)s.%(funcName)s:"
                                      "%(lineno)d - %(message)s")
        hdlr = logging.handlers.SysLogHandler(address="/dev/log")
# if file output then handler is file
    elif log_dir:
        hdlr = logging.FileHandler(log_dir)
    else:
        print "log to console|syslog|file must be set..."
        sys.exit(1)
    hdlr.setFormatter(formatter)
    LOG_PARSER.addHandler(hdlr)


def set_verb(verb):
    """
    set verbosity level
    : param verb: level (string)
    """
# logging depends on verbosity level
    if verb == "0":
        LOG_PARSER.setLevel(logging.CRITICAL)
    elif verb == "1":
        LOG_PARSER.setLevel(logging.ERROR)
    elif verb == "2":
        LOG_PARSER.setLevel(logging.INFO)
    elif verb == "3":
        LOG_PARSER.setLevel(logging.DEBUG)
    else:
        LOG_PARSER.error("verbose level must be 0, 1, 2 or 3...")
        sys.exit(1)


def parse_file(path):
    """
    determine file type, parse it and return valid JSON/PKL dictionary
    or emty dictionary if file is corrupted
    or not valid JSON/PKL or it does not exist
    : param path: file name (string)
    : return {}|parsed_data: parsed dictionary JSON/PKL (dict)
    """
# JSON/PKL formats definition
    formats = {"json": lambda x: json.loads(x),
               "pickle": lambda x: pickle.loads(x)}
    try:
# try to read file
        with open(path, "r") as file_input:
# load data from file as string
            load_data = file_input.read()
    except IOError:
# warning if file does not exist
        LOG_PARSER.debug("output file does not exist...")
# return empty dictionary if file does not exist
        return {}
# try to parse as JSON/PKL dictionary
    for frmt in formats.keys():
        try:
# try to parse loaded data as valid JSON/PKL dictionary
            parsed_data = formats[frmt](load_data)
# check if parsed data is dictionary
            if type(parsed_data) == dict:
                LOG_PARSER.debug("output file parsed as valid JSON/PKL...")
# return parsed data from file as valid JSON/PKL dictionary
                return parsed_data
            else:
# return empty dictionary if it is not valid = not a dictionary
                LOG_PARSER.warning("output file is not valid JSON/PKL...")
                return {}
        except:
# do nothing, try next iteration and next format
            pass
# warning if loaded data not parsed as defined JSON/PKL
    LOG_PARSER.warning("output file is not JSON/PKL or corrupted...")
# return empty dictionary if loaded data not JSON/PKL or corrupted
    return {}


def parse_msg(message):
    """
    parse string as email message, fill the dictionary with particular fields
    log warnings if message does not have fields FROM, TO or BODY of message
    log error if message does not have FROM&TO
    fields both and return empty dictionary
    : param message: message (string)
    : return dct: dictionary with parsed fields and it's content (dict)
    """
# defaults
    dct = {}
# try to get FROM field
    if message.get("from"):
# create dictionary entry as list of valid emails
        dct["from"] = email_addr_count(message["from"])
# warning if it does not have valid emails
        if len(dct.get("from", [])) == 0:
            LOG_PARSER.warning("MSG does not have valid email"
                               " address *FROM*")
# warning if it does not have field FROM
    else:
        LOG_PARSER.warning("MSG does not contain field *FROM*")
# try to get TO field
    if message.get("to"):
# create dictionary entry as list of valid emails
        dct["to"] = email_addr_count(message["to"])
# warning if it does not have valid emails
        if len(dct.get("to", [])) == 0:
            LOG_PARSER.warning("MSG does not have valid email"
                                   " address *TO*")
# warning if it does not have field TO
    else:
        LOG_PARSER.warning("MSG does not contain field *TO*")
# try to get CC field and create dictionary entry
    if message.get("cc"):
        dct["cc"] = email_addr_count(message["cc"])
# try to get BCC field and create dictionary entry
    if message.get("bcc"):
        dct["bcc"] = email_addr_count(message["bcc"])
# try to get BODY of message
    if message.get_payload():
# get the string = BODY of message
        body = get_body(message)
# parsing BODY for valid emails&urls and create dictionary entries
        dct["bodyemails"] = email_addr_count(body)
        dct["bodyurls"] = url_addr_count(body)
# warning if it does not have valid emails&urls
        if len(dct.get("bodyemails",
                       [])) == 0 and len(dct.get("bodyurls",
                       [])) == 0:
            LOG_PARSER.warning("MSG does not contain any"
                               " url or email address in *BODY*")
# warning if message does not have BODY
    else:
        LOG_PARSER.warning("MSG does not contain field *BODY*")
    return dct


def dct_merge(d_curr, d_prev):
    """
    merging two dictionaries of emails&urls and updating input dictionary
    : param d_curr: current/new dictionary (dict)
    : param d_prev: previous/old dictionary (dict)
    : return d_prev: merged/updated dictionary (dict)
    """
# updating previous/old dictionary from current/new
    for key in d_curr.keys():
# check if url
        if "://" in key:
# add current/new value to previous/old dictionary and update matched urls
            d_prev[key] = d_prev.get(key, 0) + d_curr[key]
# if not url then email
        else:
# check if current/new email matched previous/old email
            if key in d_prev.keys():
# for matched new/old emails
                for key_email in d_curr[key].keys():
# update old email values by new email values
                    d_prev[key][key_email] = d_prev[key].get(key_email, 0) \
                                             + d_curr[key][key_email]
# update old dictionary by new email
            else:
                d_prev[key] = d_curr[key]
    return d_prev


def save_out(d_curr, o_file, o_format):
    """
    save results to output file in JSON|PKL format
    : param d_curr: current dictionary with updated content (dct)
    : param o_file: output filename (string)
    : param o_format: output format: "JSON" | "PKL"
    """
# create output data as JSON/PKL
    if o_format == "JSON":
        LOG_PARSER.debug("create JSON file...")
        to_file = json.dumps(d_curr)
    elif o_format == "PKL":
        LOG_PARSER.debug("create PKL file...")
        to_file = pickle.dumps(d_curr)
# file type must be a JSON/pickle
    else:
        LOG_PARSER.error("file type must be a JSON or PKL...")
        sys.exit(1)
# write output data to file
    with open(o_file, "w") as file_out:
        LOG_PARSER.debug("write output file...")
        file_out.write(to_file)


def get_body(msg):
    """
    parse message body as multipart message or not multipart
    : param msg: message (instance)
    : return text: body as decoded string/empty string if no body (str)
    """
# try to get BODY of message
    body_content = ""
    body_parts = []
# if message multipart
    if msg.is_multipart():
        LOG_PARSER.debug("MSG has *MULTIPART* body")
# for each part of message body
        for part in msg.walk():
            charset = part.get_content_charset()
# if content is text then create/append a list of parts
            if part.get_content_type() in ("text/plain", "text/html"):
                body_parts.append(unicode(part.get_payload(decode=True),
                                  str(charset),
                                  "ignore").encode("utf8", "replace"))
# get one string from list of content parts
        body_content = "".join(body_parts)
# if message not multipart = string
    else:
# decode contents as one string
        body_content = unicode(msg.get_payload(decode=True),
                               str(msg.get_content_charset()),
                               "ignore").encode("utf8", "replace")
    return body_content.strip()


def is_msg_parsed(hash_data, hash_sign):
    """
    count message checksum and compare it checksum
    with current dictionary that contains checksums of
    previously parsed messages depending on hash sign
    : param hash_data: data to count hash (string)
    : param hash_sign: checksum counts as FILE|BODY (string)
    : return True|False: True if message was parsed | False if not (boolean)
    """
# get checksum of hash data
    encrypted = hashlib.md5(hash_data).hexdigest()
# check if checksum stored in global hash dictionary with particular hash sign
    if hash_dct.get(hash_sign, {}).get(encrypted):
        LOG_PARSER.debug("*HASH* message was parsed...")
# message was parsed = True and return old dictionary
        return True
# if checksum is not in hash dictionary
    else:
# updating global hash dictionary with hash of new message
        hash_dct.setdefault(hash_sign, {})[encrypted] = 1
# message was not parsed = False and return updated dictionary
        LOG_PARSER.debug("*HASH* dictionary was updated...")
        return False


def read_hash(hash_file):
    """
    read checksums file in JSON format and return current dictionary
    if file does not exist return empty dictionary {}
    : param hash_file: output filename (string)
    : return hash_data: dictionary of hashes (dct)
    """
# try to read file with checksums if it exists
    try:
        with open(hash_file, "r") as chksum_file:
            hash_data = json.loads(chksum_file.read())
        LOG_PARSER.debug("*HASH* read the hash data...")
# check if the hash data is correct dictionary
        if type(hash_data) == dict:
            LOG_PARSER.debug("*HASH* file parsed as valid JSON...")
# return hash data from file as valid dictionary
            return hash_data
# return empty dictionary if file is not a valid JSON or not exist
    except:
        LOG_PARSER.warning("*HASH* file is corrupted or does not exist...")
        return {}


def save_hash(hash_file):
    """
    save results to output checksums file in JSON format
    : param hash_file: output filename (string)
    """
# check if file with checksums exist
    if not os.path.isfile(hash_file):
        LOG_PARSER.debug("*HASH* file does not exist...")
# write output data to file if not empty
    if hash_dct != {}:
# save output data as JSON/PKL
        LOG_PARSER.debug("*HASH* save the hash file as JSON...")
        with open(hash_file, "w") as file_out:
            file_out.write(json.dumps(hash_dct))
# log if hash is empty
    else:
        LOG_PARSER.debug("*HASH* nothing to save...")
    return


def msg_from_file(file_name, o_file, o_format, hash_sign):
    """
    parsing file as MSG, find emails and urls in fields and log
    check if message valid or not, parsed or not
    : param file_name: input filename/folder (string)
    : param o_file: output filename (string)
    : param o_format: output format: "JSON" | "PKL"
    : param hash_sign: checksum counts as FILE|BODY (string)
    """
# get the data from file
    with open(file_name, "r") as file_to_read:
        load_data = file_to_read.read()
# parse loaded data as email message
    message = email.message_from_string(load_data)
# if data from file does not have fields FROM&TO then it does not valid message
    if (not message.get("from")) and (not message.get("to")):
        LOG_PARSER.error("MSG is not a valid email message...")
        return
# get the hash data as string depending on FILE hash sign
    if hash_sign == "FILE":
        hash_data = load_data
# get the only body of message as hash data depending on BODY hash sign
    elif hash_sign == "BODY":
        hash_data = get_body(message)
# must be set only a FILE/BODY
    else:
        LOG_PARSER.error("*HASH* counts only a FILE/BODY checksum...")
        sys.exit(1)
# check if message was parsed
    if is_msg_parsed(hash_data, hash_sign):
        return
# parsing content of message
    dct = parse_msg(message)
# create lists of emails&urls from current dictionary
    email_list, url_list = lst_from_dct(dct)
# create current/new dictionary of emails&urls
    d_curr = email_url_dct(dct, email_list, url_list)
# update current/new dictionary from file
    d_curr = dct_merge(d_curr, parse_file(o_file))
# save output if current parsed MSG is not empty
    if d_curr != {}:
        save_out(d_curr, o_file, o_format)
    return
# end of functions


def main():
    """
    main module
    """
# globals
    global hash_dct
# defaults
    usage = "usage: %prog -c CONFIGFILE"
# parsing the CLI string for options and arguments
    mailparser = optparse.OptionParser(usage,
                epilog = "MSG parser - "
                "parse MSG file for valid emails&urls, "
                "save result and log")
    mailparser.add_option("-c", "--config", dest="cfg", default="default.cfg",
                          help="read from CONFIGFILE")
    try:
        options, args = mailparser.parse_args()
# set options from INI file if exist, all options will be overriden
        config = ConfigParser.SafeConfigParser({"filename": "",
                                                "output": "",
                                                "type": "",
                                                "logfile": "",
                                                "verbose": "",
                                                "hasfile": "",
                                                "hashsign": ""})
# if config INI is set just read actual options from INI
        if os.path.isfile(options.cfg):
            config.read(options.cfg)
            filename = config.get("msg","filename")
            output =  config.get("msg","output")
            savetype = config.get("msg","type")
            logfile = config.get("msg","logfile")
            verbose = config.get("msg","verbose")
            hashfile = config.get("msg","hashfile")
            hashsign = config.get("msg","hashsign")
            if not (filename and output and savetype and logfile and
                    verbose and hashfile and hashsign):
                mailparser.print_help()
                print "wrong format or data in CONFIGFILE..."
                sys.exit(1)
        else:
            mailparser.print_help()
            print "CONFIGFILE must exist..."
            sys.exit(1)
# set logging stream direction
        set_log_stream(logfile)
# set verbosity level
        set_verb(verbose)
# get hash dictionary from hash file and set global hash dictionary
        hash_dct = read_hash(hashfile)
# parse directory/file
        if filename:
# if directory
            if os.path.isdir(filename):
# for files in directory only
                for file_name in os.listdir(filename):
# only if file, it does not parse directory in directory
                    if os.path.isfile(os.path.join(filename, file_name)):
# call the function for each file
                        msg_from_file(os.path.join(filename, file_name),
                                      output,
                                      savetype,
                                      hashsign)
# call the function for particular file
            elif os.path.isfile(filename):
                msg_from_file(filename,
                              output,
                              savetype,
                              hashsign)
            else:
                LOG_PARSER.error("file does not exist...")
                sys.exit(1)
# input file must be set
        else:
            mailparser.print_help()
            LOG_PARSER.error("FILENAME must be set...")
            sys.exit(1)
# put current hash dictionary to file
        save_hash(hashfile)
# if something went wrong in general get exception info for debugging
    except Exception:
#        mailparser.print_help()
        print ("general exception...")
        print sys.exc_info()
#        LOG_PARSER.error("general exception...")
#        LOG_PARSER.error(sys.exc_info())
        sys.exit(1)


if __name__ == "__main__":
#    import doctest
#    doctest.testmod()
    main()
