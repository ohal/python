#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ohal@softserevinc.com
#
"""
database module for MSG parser
"""


# import modules
import logging
import MySQLdb as mdb


# set default logger
db_logger = logging.getLogger("mparser")


# sql decorator
def query_wrapper(sql):
    """
    query decorator
    """
    def wrapper(self, *args, **kwargs):
        """
        query wrapper
        """
        try:
            conn = mdb.connect(self.host,
                               self.user,
                               self.passwd,
                               self.d_base,
                               use_unicode=True)
            conn.set_character_set("utf8")
            cur = conn.cursor()
            cur.execute("SET NAMES utf8;")
            cur.execute("SET AUTOCOMMIT=1;")
#            print "wrapper args: %s, kwargs: %s" % (args, kwargs)
# pass cursor as argument
            data = sql(self, cur)
        except mdb.Error, e_mdb:
            db_logger.error("*DB* error %d: %s" %
                            (e_mdb.args[0], e_mdb.args[1]))
            data = None
        finally:
            conn.close()
#            print "wrapper data", data
            return data
    return wrapper


# classes
class ParserDB(object):
    """
    mail parser database
    """
    def __init__(self, host, user, passwd, d_base):
        """
        constructor
        """
        self.host = host
        self.user = user
        self.passwd = passwd
        self.d_base = d_base


# methods
    def db_show(self):
        """
        show whole database
        """
        @query_wrapper
        def inner(self, *args, **kwargs):
            """
            inner sql
            """
#            print "db show args: %s, kwargs: %s" % (args, kwargs)
# set cursor from argument
            cur = args[0]
            print "DATABASE, 'hashes' table"
            cur.execute("SELECT * "
                        "FROM hashes;")
            rows = cur.fetchall()
            for row in rows:
                print ("SIGN %s CRC %s" % (row[1], row[0]))
            print "DATABASE, 'emails' table"
            cur.execute("SELECT * "
                        "FROM emails;")
            rows = cur.fetchall()
            for row in rows:
                print ("EMAIL %s FROM %s TO %s CC %s BCC %s BODY %s" %
                       (row[0], row[1], row[2], row[3], row[4], row[5]))
            print "DATABASE, 'urls' table"
            cur.execute("SELECT * "
                        "FROM urls;")
            rows = cur.fetchall()
            for row in rows:
                print ("URL %s REACHABLE %s EMAILS %s URLS %s" %
                       (row[0], row[1], row[2], row[3]))
        return inner(self)


    def hash_check(self, hash_val, hash_met):
        """
        check if hash stored in database
        """
        @query_wrapper
        def inner(self, *args, **kwargs):
            """
            inner sql
            """
#            print "hash check: %s, %s" % (args, kwargs)
#            print hash_val, hash_met
# set cursor from argument
            cur = args[0]
            cur.execute("SELECT 1 "
                        "FROM hashes "
                        "WHERE hash = '%s' "
                        "AND sign = '%s';" %
                        (hash_val, hash_met))
            query = cur.fetchone()
#            print "query", query
            return query
        return inner(self)


    def hash_save(self, hash_val, hash_met):
        """
        store hash in database
        """
        @query_wrapper
        def inner(self, *args, **kwargs):
            """
            inner sql
            """
#            print "hash save: %s, %s" % (args, kwargs)
#            print hash_val, hash_met
# set cursor from argument
            cur = args[0]
            cur.execute("INSERT INTO hashes (hash, sign) "
                        "VALUES ('%s', '%s');" %
                    (hash_val, hash_met))
            query = cur.fetchone()
#            print "query", query
            return query
        return inner(self)


    def url_update(self, url, data):
        """
        update database table urls
        """
        @query_wrapper
        def inner(self, *args, **kwargs):
            """
            inner sql
            """
#            print "url update: %s, %s" % (args, kwargs)
# set cursor from argument
            cur = args[0]
# if url stored
            if cur.execute("SELECT 1 "
                           "FROM urls "
                           "WHERE url = '%s';" %
                           (url,)):
# update record in database with new data
                cur.execute("UPDATE urls "
                            "SET reach=%s, cemails=%s, curls=%s "
                            "WHERE url='%s';" %
                            (data.get("reachable", 0),
                             data.get("emails", 0),
                             data.get("urls", 0),
                             url))
                db_logger.debug("*DB* table urls updated %s" % (url,))
            else:
# insert record in database, if it's not in database
                cur.execute("INSERT INTO urls (url, reach, cemails, curls) "
                            "VALUES ('%s', %s, %s, %s)" %
                            (url,
                             data.get("reachable", 0),
                             data.get("emails", 0),
                             data.get("urls", 0)))
                db_logger.debug("*DB* inserted to table urls %s" % (url,))
            query = cur.fetchone()
            return query
        return inner(self)


    def email_update(self, email, data):
        """
        update database table emails
        """
        @query_wrapper
        def inner(self, *args, **kwargs):
            """
            inner sql
            """
#            print "email update: %s, %s" % (args, kwargs)
# set cursor from argument
            cur = args[0]
# if email stored
            if cur.execute("SELECT 1 "
                           "FROM emails "
                           "WHERE email = '%s';" %
                        (email,)):
# update record in database with new data
                cur.execute("UPDATE emails "
                            "SET ffrom=ffrom+%s, fto=fto+%s, fcc=fcc+%s, "
                            "fbcc=fbcc+%s, fbody=fbody+%s "
                            "WHERE email='%s';" %
                            (data.get("from", 0),
                             data.get("to", 0),
                             data.get("cc", 0),
                             data.get("bcc", 0),
                             data.get("bodyemails", 0),
                             email))
                db_logger.debug("*DB* table emails updated %s" % (email,))
            else:
# insert record in database, if it's not in database
                cur.execute("INSERT INTO emails "
                            "(email, ffrom, fto, fcc, fbcc, fbody) "
                            "VALUES ('%s', %s, %s, %s, %s, %s);" %
                            (email,
                             data.get("from", 0),
                             data.get("to", 0),
                             data.get("cc", 0),
                             data.get("bcc", 0),
                             data.get("bodyemails", 0)))
                db_logger.debug("*DB* inserted to table emails %s" % (email,))
            query = cur.fetchone()
            return query
        return inner(self)
# end of methods