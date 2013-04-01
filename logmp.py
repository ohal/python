#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ohal@softserevinc.com
#
"""
logging module for MSG parser
"""


# import modules
import os
import sys
import logging
import logging.handlers
import ConfigParser


# functions
def set_mp_logger(log_name, logcfg):
    """
    set the direction/handler of logging - console, syslog or file name
    set the logging level 0, 1, 2 or 3 = CRITICAL, ERROR, INFO, DEBUG
    : param logcnf: name of logging INI file (string)
    : return mp_logger: return a logger with the specified name (class)
    """
# default stream and loglevel
    ini_stream = "console"
    ini_level = "3"
# default logging output format
    formatter = logging.Formatter("%(asctime)s %(levelname)s:%(filename)s:"
                                  "%(module)s.%(funcName)s:"
                                  "%(lineno)d - %(message)s",
                                  "%d/%m/%Y %H:%M:%S")
# set instance class logger with name
    mp_logger = logging.getLogger(log_name)
# set options from INI file if exist, all options will be overriden
    config = ConfigParser.SafeConfigParser({"logfile": "console",
                                            "verbose": "3"})
# if config INI is set just read actual options from INI
    if os.path.isfile(logcfg):
        config.read(logcfg)
# logfile: file name for log messages
        log_stream = config.get("logging","logfile")
# verbose: verbose level for log messages
        log_level = config.get("logging","verbose")
    else:
        print "*LOG* INI file does not exist, set logging to default..."
        log_stream, log_level = ini_stream, ini_level
# logging depends on console, syslog or file output
    if log_stream == "console":
# if console output then handler is sys.stderr
        hdlr = logging.StreamHandler(sys.stderr)
    elif log_stream == "syslog":
# if syslog output then handler is /dev/syslog
        formatter = logging.Formatter("%(levelname)s:%(filename)s:"
                                      "%(module)s.%(funcName)s:"
                                      "%(lineno)d - %(message)s")
        hdlr = logging.handlers.SysLogHandler(address="/dev/log")
    else:
# if file output then handler is file
        hdlr = logging.FileHandler(log_stream)
# add the handler
    mp_logger.addHandler(hdlr)
# set logging format
    hdlr.setFormatter(formatter)
# set logging level depends on verbosity level
    if log_level == "0":
        mp_logger.setLevel(logging.CRITICAL)
    elif log_level == "1":
        mp_logger.setLevel(logging.ERROR)
    elif log_level == "2":
        mp_logger.setLevel(logging.INFO)
    elif log_level == "3":
        mp_logger.setLevel(logging.DEBUG)
    else:
# set to default level DEBUG
        mp_logger.warning("*LOG* set logging to default DEBUG loglevel...")
        mp_logger.setLevel(logging.DEBUG)
# return a logger with the specified name
    return mp_logger
