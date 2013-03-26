#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ohal@softserevinc.com
#
"""
database module for MSG parser
"""


# import modules
import sys
import logging
import MySQLdb as mdb


# set default logger
db_logger = logging.getLogger("root")


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
    def hash_check(self, hash_val, hash_met):
        """
        check if hash stored in database
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
# try to get checksum if exist
            cur.execute("SELECT 1 "
                "FROM hashes "
                "WHERE hash = %s "
                "AND sign = %s;",
                (hash_val, hash_met))
            row = cur.fetchone()
# return 1 if checksum stored
            return row
        except mdb.Error, e_mdb:
            db_logger.error("*DB* error %d: %s" %
                            (e_mdb.args[0], e_mdb.args[1]))
            sys.exit(1)
        finally:
            conn.close()
    def hash_save(self, hash_val, hash_met):
        """
        store hash in database
        """
        try:
            conn = mdb.connect(self.host,
                               self.user,
                               self.passwd,
                               self.d_base,
                               use_unicode=True)
            conn.set_character_set("utf8")
# set cursor
            cur = conn.cursor()
            cur.execute("SET NAMES utf8;")
# update table hashes with new checksum and hash sign
            cur.execute("INSERT INTO hashes (hash, sign) "
                "VALUES (%s, %s);",
                (hash_val, hash_met))
            conn.commit()
        except mdb.Error, e_mdb:
            db_logger.error("*DB* error %d: %s" %
                            (e_mdb.args[0], e_mdb.args[1]))
            sys.exit(1)
        finally:
            conn.close()
    def url_update(self, url, data):
        """
        update database table urls
        """
        try:
# try to get connector to db
            conn = mdb.connect(self.host,
                               self.user,
                               self.passwd,
                               self.d_base,
                               use_unicode=True)
            conn.set_character_set("utf8")
# set cursor
            cur = conn.cursor()
            cur.execute("SET NAMES utf8;")
# try to get url
            cur.execute("SELECT 1 "
                "FROM urls "
                "WHERE url = %s;",
                (url,))
# if url stored
            if cur.fetchone():
# update record in database with new data
                cur.execute("UPDATE urls "
                    "SET reach=%s, cemails=%s, curls=%s "
                    "WHERE url=%s;",
                    (data.get("reachable"),
                     data.get("emails"),
                     data.get("urls"),
                     url))
                db_logger.debug("*DB* table urls updated %s" % (url,))
            else:
# insert record in database, if it's not in database
                cur.execute("INSERT INTO urls (url, reach, cemails, curls) "
                    "VALUES (%s, %s, %s, %s)",
                    (url,
                     data.get("reachable"),
                     data.get("emails"),
                     data.get("urls")))
                db_logger.debug("*DB* inserted to table urls %s" % (url,))
            conn.commit()
            return
        except mdb.Error, e_mdb:
            db_logger.error("*DB* error %d: %s" %
                            (e_mdb.args[0], e_mdb.args[1]))
            sys.exit(1)
        finally:
            conn.close()
    def email_update(self, email, data):
        """
        update database table emails
        """
        try:
# try to get connector to db
            conn = mdb.connect(self.host,
                               self.user,
                               self.passwd,
                               self.d_base,
                               use_unicode=True)
            conn.set_character_set("utf8")
# set cursor
            cur = conn.cursor()
            cur.execute("SET NAMES utf8;")
# try to get email
            cur.execute("SELECT 1 "
                        "FROM emails "
                        "WHERE email = %s;",
                        (email,))
# if email stored
            if cur.fetchone():
# get the stored email data
                cur.execute("SELECT * "
                            "FROM emails "
                            "WHERE email = %s;",
                            (email,))
                e, ffrom, fto, fcc, fbcc, fbody = cur.fetchone()
# update record in database with new data
                cur.execute("UPDATE emails "
                    "SET ffrom=%s, fto=%s, fcc=%s, fbcc=%s, fbody=%s "
                    "WHERE email=%s;",
# update data
                    (data.get("from", 0) + ffrom,
                     data.get("to", 0) + fto,
                     data.get("cc", 0) + fcc,
                     data.get("bcc", 0) + fbcc,
                     data.get("bodyemails", 0) + fbody,
                     email))
                db_logger.debug("*DB* table emails updated %s" % (email,))
            else:
# insert record in database, if it's not in database
                cur.execute("INSERT INTO emails "
                    "(email, ffrom, fto, fcc, fbcc, fbody) "
                    "VALUES (%s, %s, %s, %s, %s, %s);",
                    (email,
                     data.get("from", 0),
                     data.get("to", 0),
                     data.get("cc", 0),
                     data.get("bcc", 0),
                     data.get("bodyemails", 0)))
                db_logger.debug("*DB* inserted to table emails %s" % (email,))
            conn.commit()
            return
        except mdb.Error, e_mdb:
            db_logger.error("*DB* error %d: %s" %
                            (e_mdb.args[0], e_mdb.args[1]))
            sys.exit(1)
        finally:
            conn.close()
    def show(self):
        """
        show whole database
        """
        try:
            conn = mdb.connect(self.host,
                               self.user,
                               self.passwd,
                               self.d_base,
                               use_unicode=True)
            conn.set_character_set("utf8")
# set cursor
            cur = conn.cursor()
            cur.execute("SET NAMES utf8;")
            cur.execute("SELECT * "
                        "FROM hashes;")
            print "HASHES"
            print cur.fetchall()
            cur.execute("SELECT * "
                        "FROM emails;")
            print "EMAILS"
            print cur.fetchall()
            cur.execute("SELECT * "
                        "FROM urls;")
            print "URLS"
            print cur.fetchall()
            return
        except mdb.Error, e_mdb:
            db_logger.error("*DB* error %d: %s" %
                            (e_mdb.args[0], e_mdb.args[1]))
            sys.exit(1)
        finally:
            conn.close()
