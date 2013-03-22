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
                           "AND sign = %s;", (hash_val, hash_met))
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
            cursor.execute("INSERT INTO hashes (hash, sign) \
                    VALUES ('%s', '%s')" % \
                    (hash_val, hash_met))
            conn.commit()
        except mdb.Error, e:
            db_logger.error("*DB* error %d: %s" % (e.args[0], e.args[1]))
            sys.exit(1)
        finally:
            conn.close()
