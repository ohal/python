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


#    def __query_wrapper(func):
#        def inner(*args, **kwargs):
#            print "Arguments were: %s, %s" % (args, kwargs)
#            return func(*args, **kwargs)
#        return inner
#        def inner(*args, **kwargs):
#            print "arguments - %s, %s" % (args, kwargs)
#            try:
#                conn = mdb.connect(self.host,
#                                   self.user,
#                                   self.passwd,
#                                   self.d_base,
#                                   use_unicode=True)
#                print conn
#                conn.set_character_set("utf8")
#                cur = conn.cursor()
#                cur.execute("SET NAMES utf8;")
#                cur.execute("")
#                conn.commit()
#                data = cur.fetchone()
#            except mdb.Error, e_mdb:
#                conn.rollback()
#                db_logger.error("*DB* error %d: %s" %
#                                (e_mdb.args[0], e_mdb.args[1]))
#                data = None
#            finally:
#                cur.close()
#                conn.close()
#                return data
#        return inner


#    @__query_wrapper
#    def hash_print(self, hash_val, hash_met):
#        cur.execute("SELECT 1 "
#                           "FROM hashes "
#                           "WHERE hash = '%s' "
#                           "AND sign = '%s';" %
#                           (hash_val, hash_met))
#        return


# start
    def __query(self, query):
        """
        private, database query
        """
        try:
# create connector to database
            conn = mdb.connect(self.host,
                               self.user,
                               self.passwd,
                               self.d_base,
                               use_unicode=True)
            conn.set_character_set("utf8")
            cur = conn.cursor()
            cur.execute("SET NAMES utf8;")
# try to get query data
            cur.execute(query)
            conn.commit()
            data = cur.fetchone()
# return None if exception
        except mdb.Error, e_mdb:
            conn.rollback()
            db_logger.error("*DB* error %d: %s" %
                            (e_mdb.args[0], e_mdb.args[1]))
            data = None
        finally:
# close connector and return data
            cur.close()
            conn.close()
            return data

    def hash_check(self, hash_val, hash_met):
        """
        check if hash stored in database
        """
        return self.__query("SELECT 1 "
                           "FROM hashes "
                           "WHERE hash = '%s' "
                           "AND sign = '%s';" %
                           (hash_val, hash_met))


    def hash_save(self, hash_val, hash_met):
        """
        store hash in database
        """
        self.__query("INSERT INTO hashes (hash, sign) "
                    "VALUES ('%s', '%s');" %
                    (hash_val, hash_met))
        return True


    def url_update(self, url, data):
        """
        update database table urls
        """
# if url stored
        if self.__query("SELECT 1 "
                       "FROM urls "
                       "WHERE url = '%s';" %
                       (url,)):
# update record in database with new data
            self.__query("UPDATE urls "
                        "SET reach=%s, cemails=%s, curls=%s "
                        "WHERE url='%s';" %
                        (data.get("reachable", 0),
                         data.get("emails", 0),
                         data.get("urls", 0),
                         url))
            db_logger.debug("*DB* table urls updated %s" % (url,))
        else:
# insert record in database, if it's not in database
            self.__query("INSERT INTO urls (url, reach, cemails, curls) "
                        "VALUES ('%s', %s, %s, %s)" %
                        (url,
                         data.get("reachable", 0),
                         data.get("emails", 0),
                         data.get("urls", 0)))
            db_logger.debug("*DB* inserted to table urls %s" % (url,))
        return True


    def email_update(self, email, data):
        """
        update database table emails
        """
# try to get email data
        row = self.__query("SELECT * "
                          "FROM emails "
                          "WHERE email = '%s';" %
                          (email,))
# if email stored
        if row:
# update record in database with new data
            e, ffrom, fto, fcc, fbcc, fbody = row
            self.__query("UPDATE emails "
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
            self.__query("INSERT INTO emails "
                        "(email, ffrom, fto, fcc, fbcc, fbody) "
                        "VALUES ('%s', %s, %s, %s, %s, %s);" %
                        (email,
                         data.get("from", 0),
                         data.get("to", 0),
                         data.get("cc", 0),
                         data.get("bcc", 0),
                         data.get("bodyemails", 0)))
            db_logger.debug("*DB* inserted to table emails %s" % (email,))
        return True
