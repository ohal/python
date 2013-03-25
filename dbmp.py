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
    def __init__(self, host, user, passwd, db):
        """
        constructor
        """
        self.host = host
        self.user = user
        self.passwd = passwd
        self.db = db
    def __del__(self):
        pass
    def hash_check(self, hash_val, hash_met):
        """
        check if hash stored in database
        """
        try:
            conn = mdb.connect(self.host, self.user, self.passwd, self.db)
            cursor = conn.cursor()
            cursor.execute("SELECT 1 "
                           "FROM hashes "
                           "WHERE hash = %s "
                           "AND sign = %s;",
                           (hash_val, hash_met))
            row = cursor.fetchone()
            return row
        except mdb.Error, e:
            db_logger.error("*DB* error %d: %s" % (e.args[0], e.args[1]))
            sys.exit(1)
        finally:
            conn.close()
    def hash_save(self, hash_val, hash_met):
        """
        store hash in database
        """
        try:
            conn = mdb.connect(self.host, self.user, self.passwd, self.db)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO hashes (hash, sign) "
                           "VALUES (%s, %s);",
                           (hash_val, hash_met))
            conn.commit()
        except mdb.Error, e:
            db_logger.error("*DB* error %d: %s" % (e.args[0], e.args[1]))
            sys.exit(1)
        finally:
            conn.close()
    def url_update(self, url, data):
        """
        update database table urls
        """
        try:
            conn = mdb.connect(self.host, self.user, self.passwd, self.db)
            cursor = conn.cursor()
            cursor.execute("SELECT 1 "
                           "FROM urls "
                           "WHERE url = %s;",
                           (url,))
            if cursor.fetchone():
                cursor.execute("UPDATE urls "
                               "SET reach=%s, cemails=%s, curls=%s "
                               "WHERE url=%s;",
                               (data.get("reachable"),
                                data.get("emails"),
                                data.get("urls"),
                                url))
                conn.commit()
                db_logger.debug("*DB* table urls updated %s" % (url,))
            else:
                cursor.execute("INSERT INTO urls (url, reach, cemails, curls) "
                               "VALUES (%s, %s, %s, %s)",
                               (url,
                                data.get("reachable"),
                                data.get("emails"),
                                data.get("urls")))
                conn.commit()
                db_logger.debug("*DB* inserted to table urls %s" % (url,))
            return
        except mdb.Error, e:
            db_logger.error("*DB* error %d: %s" % (e.args[0], e.args[1]))
            sys.exit(1)
        finally:
            conn.close()
    def email_update(self, email, data):
        """
        update database table emails
        """
        try:
            conn = mdb.connect(self.host, self.user, self.passwd, self.db)
            cursor = conn.cursor()
            cursor.execute("SELECT 1 "
                           "FROM emails "
                           "WHERE email = %s;",
                           (email,))
            if cursor.fetchone():
                cursor.execute("SELECT * "
                               "FROM emails "
                               "WHERE email = %s;",
                               (email,))
                e, ffrom, fto, fcc, fbcc, fbody = cursor.fetchone()
                cursor.execute("UPDATE emails "
                               "SET ffrom=%s, fto=%s, fcc=%s, fbcc=%s, fbody=%s "
                               "WHERE email=%s;",
                               (data.get("from", 0) + ffrom,
                                data.get("to", 0) + fto,
                                data.get("cc", 0) + fcc,
                                data.get("bcc", 0) + fbcc,
                                data.get("bodyemails", 0) + fbody,
                                email))
                conn.commit()
                db_logger.debug("*DB* table emails updated %s" % (email,))
            else:
                cursor.execute("INSERT INTO emails (email, ffrom, fto, fcc, fbcc, fbody) "
                               "VALUES (%s, %s, %s, %s, %s, %s);",
                               (email,
                                data.get("from", 0),
                                data.get("to", 0),
                                data.get("cc", 0),
                                data.get("bcc", 0),
                                data.get("bodyemails", 0)))
                conn.commit()
                db_logger.debug("*DB* inserted to table emails %s" % (email,))
            return
        except mdb.Error, e:
            db_logger.error("*DB* error %d: %s" % (e.args[0], e.args[1]))
            sys.exit(1)
        finally:
            conn.close()
    def show(self):
        """
        show database
        """
        try:
            conn = mdb.connect(self.host, self.user, self.passwd, self.db)
            cursor = conn.cursor()
            cursor.execute("SELECT * "
                           "FROM hashes;")
            print "HASHES"
            print cursor.fetchall()
            cursor.execute("SELECT * "
                           "FROM emails;")
            print "EMAILS"
            print cursor.fetchall()
            cursor.execute("SELECT * "
                           "FROM urls;")
            print "URLS"
            print cursor.fetchall()
            return
        except mdb.Error, e:
            db_logger.error("*DB* error %d: %s" % (e.args[0], e.args[1]))
            sys.exit(1)
        finally:
            conn.close()
