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
parser_logger = logging.getLogger("mparser")
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
    : return e_u_dct: dictionary of emails & urls (dict)
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
# return actual dictionary
    return e_u_dct


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
    : param fetch_url: method of fetching content from web, URL|SUB (str)
    : return {}: dictionary element according template (dict)
    """
# get using urllib2
    if fetch_url == "URL":
# try to get content from web and decode it
        try:
            data = urllib2.urlopen(http).read()
            #.decode("utf-8", "replace")
# is not reachable if did not get content
        except urllib2.HTTPError, e_url:
            parser_logger.warning("*HTTP* error during fetching: %s, %s" %
                                  (e_url.code, e_url.reason))
            return {"reachable": False}
        except urllib2.URLError, e_url:
            parser_logger.warning("*HTTP* error during fetching: %s" %
                                  (e_url.reason,))
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
            parser_logger.warning("*HTTP* is not reachable, %s - errors..." %
                                  (err,))
            return {"reachable": False}
# fetching method must be a URL or SUB
    else:
        parser_logger.error("*HTTP* config error, only URL|SUB, not: %s" %
                            (fetch_url,))
        sys.exit(1)
# parse content for emails&urls
    data = unicode(data, "utf-8", "ignore")
    parser_logger.debug("*HTTP* got data...")
    return {"reachable": True,
            "emails": len(email_addr_count(data)),
            "urls": len(url_addr_count(data))}


def db_update(data):
    """
    update database with emails & urls
    : param data: current/new dictionary (dict)
    """
# updating previous/old dictionary from current/new
    for key in data.keys():
# validate record length up to 255 symbols
        if len(key) > 256:
            parser_logger.warning("*DB* email or url was "
                                  "truncated to256 symbols...")
            key = key[:256]
# if current/new matched previous/old element and not url = email
        if "://" in key:
            parser_db.url_update(key, data[key])
# update old dictionary by new value
        else:
            parser_db.email_update(key, data[key])
    return


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
#    print encrypted
#    parser_db.hash_print(encrypted, hash_sign)
# check if checksum stored in database with particular hash sign
    if parser_db.hash_check(encrypted, hash_sign):
        parser_logger.debug("%s - %s - message was parsed..." %
                            (encrypted, hash_sign))
# message was parsed = True and return old dictionary
        return True
# if checksum is not in hash dictionary
    else:
# updating database with particular hash and hash sign
        parser_db.hash_save(encrypted, hash_sign)
# message was not parsed = False and return updated dictionary
        parser_logger.debug("%s - %s - new hash, database was updated..." %
                            (encrypted, hash_sign))
        return False


def msg_from_file(file_name, hash_sign, fetch_url):
    """
    parsing file as MSG, find emails and urls in fields and log
    check if message valid or not, parsed or not
    : param file_name: input filename/folder (string)
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
        parser_logger.error("%s - MSG is not a valid email message..." %
                            (file_name,))
        return
# get the hash data as string depending on FILE hash sign
    if hash_sign == "FILE":
        hash_data = load_data
# get the only body of message as hash data depending on BODY hash sign
    elif hash_sign == "BODY":
        hash_data = get_body(message)
# must be set only a FILE/BODY
    else:
        parser_logger.error("*HASH* config error, only FILE|BODY, not: %s" %
                            (hash_sign,))
        sys.exit(1)
# check if message was parsed
    if is_msg_parsed(hash_data, hash_sign):
        return False
# parsing content of message
    dct = parse_msg(message)
# create lists of emails&urls from current dictionary
    email_list, url_list = lst_from_dct(dct)
# create current/new dictionary of emails&urls
    d_curr = email_url_dct(dct, email_list, url_list, fetch_url)
# update database with actual data from parsed MSG
    db_update(d_curr)
#    parser_db.show()
    return True


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
                                            "hashsign": "",
                                            "fetchurl": ""})
# if config INI is set just read actual options from INI
    if os.path.isfile(cfg):
        config.read(cfg)
# filename: configuration file name
        filename = config.get("msg","filename")
# hashsign: count hash of message by file or body only FILE|BODY
        hashsign = config.get("msg","hashsign")
# fetchurl: method of fetching content from web URL|SUB (str)
        fetchurl = config.get("msg","fetchurl")
        if not (filename and hashsign and fetchurl):
            print "wrong format or data in CONFIGFILE..."
            sys.exit(1)
        return (filename, hashsign, fetchurl)
    else:
        print "CONFIGFILE must exist..."
        sys.exit(1)


def show_db():
    """
    show current data stored in database and exit
    """
    db_data = parser_db.db_show()
    if not db_data:
        parser_logger.warning("*DB* no data from database...")
        sys.exit(1)
    if db_data.get("hashes"):
        print "HASHES"
        print "\n".join(["HASH %s SIGN %s" % (key, value) for key,
                        value in db_data["hashes"].items()])
    else:
        print "table HASHES is empty"
    if db_data.get("emails"):
        print "EMAILS"
        print "\n".join(["EMAIL %s VALUE %s" % (key, value) for key,
                        value in db_data["emails"].items()])
    else:
        print "table EMAILS is empty"
    if db_data.get("urls"):
        print "URLS"
        print "\n".join(["URL %s VALUE %s" % (key, value) for key,
                        value in db_data["urls"].items()])
    else:
        print "table URLS is empty"
    sys.exit(0)
# end of functions


def main():
    """
    main module
    """
# globals
    global parser_logger
    global parser_db
# defaults
    usage = "usage: %prog -c CONFIGFILE " \
            "-d DATABASECONFIG " \
            "-l LOGGINGCONFIG " \
            "-s SHOWDB=0|1"
# parsing the CLI string for options and arguments
    mailparser = optparse.OptionParser(usage,
                epilog = "MSG parser - "
                "parse MSG file for valid emails&urls, "
                "save result and log")
    mailparser.add_option("-c", "--config", dest="cfg", default="default.cfg",
                          help="read from CONFIGFILE")
    mailparser.add_option("-d", "--dbcfg", dest="dbcfg", default="db.cfg",
                          help="read from DATABASECONFIG")
    mailparser.add_option("-l", "--logcfg", dest="logcfg", default="log.cfg",
                          help="read from LOGGINGCONFIG")
    mailparser.add_option("-s", "--showdb", dest="showdb", default="0",
                          help="show data from DATABASE")
    try:
        (options, args) = mailparser.parse_args()
#        print "options", options
# set mail parser from INI
        (filename, hashsign, fetchurl) = set_mp_ini(options.cfg)
# set database from INI
        (db_host, db_user, db_password, db_name) = set_db_ini(options.dbcfg)
# set logging
        parser_logger = logmp.set_mp_logger("mparser", options.logcfg)
# set database
        parser_db = dbmp.ParserDB(db_host, db_user, db_password, db_name)
# show data from database
        if options.showdb == "1":
            show_db()
            sys.exit(0)
        elif options.showdb not in ("1", "0"):
            parser_logger.error("*CFG* bad SHOWDB option...")
            sys.exit(1)
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
                                      hashsign,
                                      fetchurl)
# call the function for particular file
            elif os.path.isfile(filename):
                msg_from_file(filename,
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
        import traceback
#        mailparser.print_help()
        print("generic exception: \n %s" % (traceback.format_exc(),))
#        print sys.exc_info()
#        parser_logger.error("general exception...")
#        parser_logger.error(sys.exc_info())
        sys.exit(1)


if __name__ == "__main__":
#    import doctest
#    doctest.testmod()
    main()
