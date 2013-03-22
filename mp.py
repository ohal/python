#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ohal@softserevinc.com
#
"""
MSG parser - parse email message, found emails and urls
: param: input configuration file name
: return: save output to file serialize as JSON/PKL, 
          log to console/syslog/file,
          save hash of parsed messages and serialize to JSON
example -
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
import ConfigParser
import json
import pickle
import hashlib
import urllib2
import subprocess
# import submodules
import dbmp
import logmp

# constants
RE_EMAIL = u"[\w\.=-]+@(?:[\w-]+\.)+[a-z]{2,4}"
#RE_EMAIL = '[\w\.=-]+@([a-z0-9-]+)(\.)([a-z]{2,4})(\.?)([a-z]{0,4})'
#RE_EMAIL = '[\w\.=-]+@[\w\.-]+\.[\w]{2,3}'
RE_URL = u"https?:\/\/[^ \n\r\"<>]+"
#[^\"<>]+"
#(?=[\s\.,$])' <- look-ahead


# global defaults
parser_logger = logging.getLogger("root")
parser_db = None

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
    return sorted(list(re.findall(RE_EMAIL, inp, re.UNICODE)))


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
    return sorted(list(re.findall(RE_URL, inp, re.UNICODE)))


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
            parser_logger.debug("%s " % ", ".join(set(dct[k])) +
                             "%s" % k.upper())
# add each email to list
            email_list.extend(dct[k])
# collect the urls and create the list of urls
    if dct.get("bodyurls"):
# log urls parsing
        parser_logger.debug("%s " % ", ".join(set(dct["bodyurls"])) +
                         "%s" % "bodyurls".upper())
# create the list of urls
        url_list = list(dct["bodyurls"])
# log the statistic
    parser_logger.debug("---")
    parser_logger.debug("Total e-mail addresses %s" % \
                     len(set(email_list)))
    parser_logger.debug("Total URLs %s" % \
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


def email_url_dct(dct, email_list, url_list, fetch_url):
    """
    parsing dictionary, list of emails and urls and create dictionary
    of emails&urls without duplicates and counts it in each field
    : param dct: input dictionary (dict)
    : param email_list: list of emails (list)
    : param url_list: list of urls (list)
    : param fetch_url: method of fetching content from web URL|SUB (str)
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
        e_u_dct[url_key] = get_http(url_key, fetch_url)
#        print fetch_url, "-", e_u_dct[url_key]
#        e_u_dct[url_key] = dct["bodyurls"].count(url_key)
    return e_u_dct


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
        parser_logger.debug("output file does not exist...")
# return empty dictionary if file does not exist
        return {}
# try to parse as JSON/PKL dictionary
    for frmt in formats.keys():
        try:
# try to parse loaded data as valid JSON/PKL dictionary
            parsed_data = formats[frmt](load_data)
# check if parsed data is dictionary
            if type(parsed_data) == dict:
                parser_logger.debug("output file parsed as valid JSON/PKL...")
# return parsed data from file as valid JSON/PKL dictionary
                return parsed_data
            else:
# return empty dictionary if it is not valid = not a dictionary
                parser_logger.warning("output file is not valid JSON/PKL...")
                return {}
        except:
# do nothing, try next iteration and next format
            pass
# warning if loaded data not parsed as defined JSON/PKL
    parser_logger.warning("output file is not JSON/PKL or corrupted...")
# return empty dictionary if loaded data not JSON/PKL or corrupted
    return {}


def parse_msg(message):
    """
    parse string as email message, fill the dictionary with particular fields
    log warnings if message does not have fields FROM, TO or BODY of message
    log error if message does not have FROM&TO
    fields both and return empty dictionary
    : param message: message object structure (instance)
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
            parser_logger.warning("MSG does not have valid email"
                               " address *FROM*")
# warning if it does not have field FROM
    else:
        parser_logger.warning("MSG does not contain field *FROM*")
# try to get TO field
    if message.get("to"):
# create dictionary entry as list of valid emails
        dct["to"] = email_addr_count(message["to"])
# warning if it does not have valid emails
        if len(dct.get("to", [])) == 0:
            parser_logger.warning("MSG does not have valid email"
                                   " address *TO*")
# warning if it does not have field TO
    else:
        parser_logger.warning("MSG does not contain field *TO*")
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
            parser_logger.warning("MSG does not contain any"
                               " url or email address in *BODY*")
# warning if message does not have BODY
    else:
        parser_logger.warning("MSG does not contain field *BODY*")
    return dct


def get_http(http, fetch_url):
    """
    using urllib2 or subprocess
    to get the content from web and
    count emails & urls in it, fill dictionary as next -
        if web is up {"reachable": True,
                      "emails": amount of emails in body of message,
                      "urls": amount of urls in body of message}
        if web is down {"reachable": False}
    : param http: url (str)
    : param fetch_url: method of fetching content from web URL|SUB (str)
    : return {}: dictionary element according template (dict)
    """
# get using urllib2
    if fetch_url == "URL":
# try to get content from web and decode it
        try:
            data = urllib2.urlopen(http).read()
            #.decode("utf-8", "replace")
# is not reachable if did not get content
        except:
            parser_logger.warning("*HTTP* is not reachable...")
#            print sys.exc_info()
            return {"reachable": False}
# get using subprocess
    elif fetch_url == "SUB":
# try to get content from web
        p_wget = subprocess.Popen("wget '%s' -qO- \
                            --no-check-certificate \
                            --tries=3 \
                            --timeout=15 \
                            --no-cache \
                            --delete-after \
                            --user-agent=Mozilla/4.0 \
                            \(compatible\
                            \; MSIE 5.5\; Windows NT\)" %(http,),
                             shell = True,
                             stdout = subprocess.PIPE,
                             stderr = subprocess.STDOUT)
        (data, err) = p_wget.communicate()
# if did not return content and exit code not 0
        if not data:
            parser_logger.warning("*HTTP* is not reachable...")
            return {"reachable": False}
# fetching method must be a URL or SUB
    else:
        parser_logger.error("*CFG* fetching method must be URL or SUB...")
        sys.exit(1)
# parse content for emails&urls
    data = unicode(data, "utf-8", "ignore")
    parser_logger.debug("*HTTP* got data...")
    return {"reachable": True,
            "emails": len(email_addr_count(data)),
            "urls": len(url_addr_count(data))}


def dct_merge(d_curr, d_prev):
    """
    merging two dictionaries of emails&urls and updating input dictionary
    : param d_curr: current/new dictionary (dict)
    : param d_prev: previous/old dictionary (dict)
    : return d_prev: merged/updated dictionary (dict)
    """
# updating previous/old dictionary from current/new
    for key in d_curr.keys():
# if current/new matched previous/old element and not url = email
        if (key in d_prev.keys()) and ("://" not in key):
            for key_email in d_curr[key].keys():
                d_prev[key][key_email] = d_prev[key].get(key_email, 0) + \
                                         d_curr[key][key_email]
# update old dictionary by new value
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
        parser_logger.debug("create JSON file...")
        to_file = json.dumps(d_curr)
    elif o_format == "PKL":
        parser_logger.debug("create PKL file...")
        to_file = pickle.dumps(d_curr)
# file type must be a JSON/pickle
    else:
        parser_logger.error("*CFG* file type must be a JSON or PKL...")
        sys.exit(1)
# write output data to file
    with open(o_file, "w") as file_out:
        parser_logger.debug("write output file...")
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
        parser_logger.debug("MSG has *MULTIPART* body")
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
    count message checksum and compare it
    with current dictionary that contains checksums of
    previously parsed messages depending on hash sign
    : param hash_data: data to count hash (string)
    : param hash_sign: checksum counts as FILE|BODY (string)
    : return True|False: True if message was parsed | False if not (boolean)
    """
# get checksum of hash data
    encrypted = hashlib.md5(hash_data).hexdigest()
# check if checksum stored in database with particular hash sign
    if parser_db.hash_check(encrypted, hash_sign):
        parser_logger.debug("%s - %s - message was parsed..." % (encrypted, hash_sign))
# message was parsed = True and return old dictionary
        return True
# if checksum is not in hash dictionary
    else:
# updating database with particular hash and hash sign
        parser_db.hash_save(encrypted, hash_sign)
# message was not parsed = False and return updated dictionary
        parser_logger.debug("%s - %s - new hash, database was updated..." % (encrypted, hash_sign))
        return False


def msg_from_file(file_name, o_file, o_format, hash_sign, fetch_url):
    """
    parsing file as MSG, find emails and urls in fields and log
    check if message valid or not, parsed or not
    : param file_name: input filename/folder (string)
    : param o_file: output filename (string)
    : param o_format: output format: "JSON" | "PKL"
    : param hash_sign: checksum counts as FILE|BODY (string)
    : param fetch_url: method of fetching content from web URL|SUB (str)
    """
# get the data from file
    with open(file_name, "r") as file_to_read:
        load_data = file_to_read.read()
# parse loaded data as email message
    message = email.message_from_string(load_data)
# if data from file does not have fields FROM&TO then it does not valid message
    if (not message.get("from")) and (not message.get("to")):
        parser_logger.error("%s - MSG is not a valid email message..." % (file_name,))
        return
# get the hash data as string depending on FILE hash sign
    if hash_sign == "FILE":
        hash_data = load_data
# get the only body of message as hash data depending on BODY hash sign
    elif hash_sign == "BODY":
        hash_data = get_body(message)
# must be set only a FILE/BODY
    else:
        parser_logger.error("*HASH* counts only a FILE/BODY checksum...")
        sys.exit(1)
# check if message was parsed
#    if is_msg_parsed(hash_data, hash_sign):
#        return
# parsing content of message
    dct = parse_msg(message)
# create lists of emails&urls from current dictionary
    email_list, url_list = lst_from_dct(dct)
# create current/new dictionary of emails&urls
    d_curr = email_url_dct(dct, email_list, url_list, fetch_url)
    print d_curr
# update current/new dictionary from file
    d_curr = dct_merge(d_curr, parse_file(o_file))
    print d_curr
# save output if current parsed MSG is not empty
    if d_curr != {}:
        save_out(d_curr, o_file, o_format)
    return


def set_db_ini(dbcfg):
    """
    read and return database parameters from INI file
    : param dbcfg: input filename/folder (string)
    : return host, user, password, name: list of parameters (list)
    """
# set database options from INI file if exist, all options will be overriden
    confdb = ConfigParser.SafeConfigParser({"host": "",
                                             "user": "",
                                             "password": "",
                                             "dbname": ""})
    if os.path.isfile(dbcfg):
        confdb.read(dbcfg)
        host = confdb.get("db","host")
        user =  confdb.get("db","user")
        password = confdb.get("db","password")
        name = confdb.get("db","dbname")
        if not (host and user and password and name):
            print "wrong format or data in DATABASECONFIG..."
            sys.exit(1)
        return (host, user, password, name)
    else:
        print "DATABASECONFIG must exist..."
        sys.exit(1)


def set_mp_ini(cfg):
    """
    read and return mail parser parameters from INI file
    : param cfg: input filename/folder (string)
    : return filename, output, savetype, logfile,
      verbose, hashsign, fetchurl: list of parameters (list)
    """
# set options from INI file if exist, all options will be overriden
    config = ConfigParser.SafeConfigParser({"filename": "",
                                            "output": "",
                                            "type": "",
                                            "logfile": "",
                                            "verbose": "",
                                            "hashsign": "",
                                            "fetchurl": ""})
# if config INI is set just read actual options from INI
    if os.path.isfile(cfg):
        config.read(cfg)
# filename: configuration file name
        filename = config.get("msg","filename")
# output: output file name
        output =  config.get("msg","output")
# savetype: output format JSON|PKL
        savetype = config.get("msg","type")
# logfile: file name for log messages
        logfile = config.get("msg","logfile")
# verbose: verbose level for log messages
        verbose = config.get("msg","verbose")
# hashsign: count hash of message by file or body only FILE|BODY
        hashsign = config.get("msg","hashsign")
# fetchurl: method of fetching content from web URL|SUB (str)
        fetchurl = config.get("msg","fetchurl")
        if not (filename and output and savetype and logfile and
                verbose and hashsign and fetchurl):
            print "wrong format or data in CONFIGFILE..."
            sys.exit(1)
        return (filename, output, savetype, logfile,
                verbose, hashsign, fetchurl)
    else:
        print "CONFIGFILE must exist..."
        sys.exit(1)
# end of functions


def main():
    """
    main module
    """
# globals
    global parser_logger
    global parser_db
#    global db_host, db_user, db_password, db_name
# defaults
    usage = "usage: %prog -c CONFIGFILE -d DATABASECONFIG"
# parsing the CLI string for options and arguments
    mailparser = optparse.OptionParser(usage,
                epilog = "MSG parser - "
                "parse MSG file for valid emails&urls, "
                "save result and log")
    mailparser.add_option("-c", "--config", dest="cfg", default="default.cfg",
                          help="read from CONFIGFILE")
    mailparser.add_option("-d", "--dbcfg", dest="dbcfg", default="db.cfg",
                          help="read from DATABASECONFIG")
    try:
        (options, args) = mailparser.parse_args()
# set mail parser from INI
        (filename, output, savetype, logfile,
         verbose, hashsign, fetchurl) = set_mp_ini(options.cfg)
# set database from INI
        (db_host, db_user, db_password, db_name) = set_db_ini(options.dbcfg)
# set logging
        parser_logger = logmp.set_mp_logger("root", logfile, verbose)
# set database
        parser_db = dbmp.ParserDB(db_host, db_user, db_password, db_name)
#        print parser_db
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
                                      hashsign,
                                      fetchurl)
# call the function for particular file
            elif os.path.isfile(filename):
                msg_from_file(filename,
                              output,
                              savetype,
                              hashsign,
                              fetchurl)
            else:
                parser_logger.error("*CFG* file does not exist...")
                sys.exit(1)
# input file must be set
        else:
            mailparser.print_help()
            parser_logger.error("*CFG* FILENAME must be set...")
            sys.exit(1)
# if something went wrong in general get exception info for debugging
    except Exception:
#        mailparser.print_help()
        print ("general exception...")
        print sys.exc_info()
#        parser_logger.error("general exception...")
#        parser_logger.error(sys.exc_info())
        sys.exit(1)


if __name__ == "__main__":
#    import doctest
#    doctest.testmod()
    main()
