#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ohal@softserevinc.com
#
"""
logging module for MSG parser
"""


# import modules
import sys
import logging
import logging.handlers


# functions
def set_mp_logger(log_name, log_stream, log_level):
    """
    set the direction/handler of logging - console, syslog or file name
    set the logging level 0, 1, 2 or 3 = CRITICAL, ERROR, INFO, DEBUG
    : param log_name: name of logger in hierarchy (string)
    : param log_stream: logging direction console|syslog|file name (string)
    : param log_level: logging level 0|1|2|3 (string)
    : return mp_logger: return a logger with the specified name (class)
    """
# logging depends on console, syslog or file output
    formatter = logging.Formatter("%(asctime)s %(levelname)s:%(filename)s:"
                                  "%(module)s.%(funcName)s:"
                                  "%(lineno)d - %(message)s",
                                  "%d/%m/%Y %H:%M:%S")
# if console output then handler is sys.stderr
    if log_stream == "console":
        hdlr = logging.StreamHandler(sys.stderr)
# if syslog output then handler is /dev/syslog
    elif log_stream == "syslog":
        formatter = logging.Formatter("%(levelname)s:%(filename)s:"
                                      "%(module)s.%(funcName)s:"
                                      "%(lineno)d - %(message)s")
        hdlr = logging.handlers.SysLogHandler(address="/dev/log")
# if file output then handler is file
    elif log_stream:
        hdlr = logging.FileHandler(log_stream)
    else:
        print ("*LOG* config error, only console|syslog|file, not: %s" %
               (log_stream,))
        sys.exit(1)
# set instance class logger with name
    mp_logger = logging.getLogger(log_name)
# set the handler
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
        mp_logger.error("*LOG* verbose level must be 0|1|2|3, not: %s" %
                        (log_level,))
        sys.exit(1)
# return a logger with the specified name
    return mp_logger
# end of functions
