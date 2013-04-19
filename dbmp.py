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
def query_wrapper(db_obj):
    """
    database query decorator, got an object
    """
    def sql_wrapper(sql):
        """
        function wrapper, got a function
        """
        def wrapper(*args, **kwargs):
            """
            query wrapper, got args, kwargs
            """
#            print db_obj
#            print sql
#            print "wrapper args: %s, kwargs: %s" % (args, kwargs)
            try:
                conn = mdb.connect(db_obj.host,
                                   db_obj.user,
                                   db_obj.passwd,
                                   db_obj.d_base,
                                   use_unicode=True)
                try:
                    conn.set_character_set("utf8")
                    cur = conn.cursor()
                    cur.execute("SET NAMES utf8;")
                    cur.execute("SET AUTOCOMMIT=1;")
# pass all arguments, cursor as well
                    data = sql(cur, *args, **kwargs)
                    cur.close()
                except mdb.Error, e_mdb:
                    db_logger.error("*DB* cursor error %d: %s" %
                                    (e_mdb.args[0], e_mdb.args[1]))
                    data = None
                finally:
                    conn.close()
            except mdb.Error, e_mdb:
                db_logger.error("*DB* connector error %d: %s" %
                                (e_mdb.args[0], e_mdb.args[1]))
                data = None
#            print data
            return data
        return wrapper
    return sql_wrapper


# classes
class ParserDB(object):
    """
    mail parser database
    """
# constructor
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
        @query_wrapper(self)
        def inner(cur):
            """
            inner sql
            """
            db_dct = {}
            b_sign = lambda x: x == u"\x01" and True or False
# set cursor from argument
            cur.execute("SELECT * "
                        "FROM hashes;")
# get all from database table hashes
            rows = cur.fetchall()
# put to the dictionary selected data
            for row in rows:
                db_dct.setdefault("hashes", {}).setdefault(row[0], row[1])
# get all from database table emails
            cur.execute("SELECT * "
                        "FROM emails;")
            rows = cur.fetchall()
# put to the dictionary selected data
            for row in rows:
                for key, value in {"from": 1, "to": 2, 
                                   "cc": 3, "bcc": 4, "body": 5}.items():
                    db_dct.setdefault("emails",
                                      {}).setdefault(row[0],
                                      {}).setdefault(key, row[value])
# get all from database table urls
            cur.execute("SELECT * "
                        "FROM urls;")
            rows = cur.fetchall()
# put to the dictionary selected data
            for row in rows:
                db_dct.setdefault("urls",
                                  {}).setdefault(row[0],
                                  {}).setdefault("reachable", b_sign(row[1]))
                for key, value in {"emails": 2, "urls": 3}.items():
                    db_dct.setdefault("urls",
                                      {}).setdefault(row[0],
                                      {}).setdefault(key, row[value])
#            print db_dct
            return db_dct
        return inner()


    def hash_check(self, hash_val, hash_met):
        """
        check if hash stored in database
        """
        @query_wrapper(self)
        def inner(cur):
            """
            inner sql
            """
# set cursor from argument
            cur.execute("SELECT 1 "
                        "FROM hashes "
                        "WHERE hash = '%s' "
                        "AND sign = '%s';" %
                        (hash_val, hash_met))
            query = cur.fetchone()
            return query
        return inner()


    def hash_save(self, hash_val, hash_met):
        """
        store hash in database
        """
        @query_wrapper(self)
        def inner(cur):
            """
            inner sql
            """
# set cursor from argument
            cur.execute("INSERT INTO hashes (hash, sign) "
                        "VALUES ('%s', '%s');" %
                    (hash_val, hash_met))
            query = cur.fetchone()
            return query
        return inner()


    def url_update(self, url, data):
        """
        update database table urls
        """
        @query_wrapper(self)
        def inner(cur):
            """
            inner sql
            """
# set cursor from argument
# check if url stored
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
        return inner()


    def email_update(self, email, data):
        """
        update database table emails
        """
        @query_wrapper(self)
        def inner(cur):
            """
            inner sql
            """
# set cursor from argument
# check if email stored
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
        return inner()
# end of methods
