# coding: utf-8
__doc__ = 'default application wide settings'

import sys
import os
import logging


# default location to store output state files
dirname, filename = os.path.split(sys.argv[0])
state_dir = os.path.join(dirname, '.' + filename.replace('.py', '')) 
if not os.path.exists(state_dir):
    try:
        os.mkdir(state_dir)
    except OSError as e:
        state_dir = ''
        #print 'Unable to create state directory:', e
cache_file  = os.path.relpath(os.path.join(state_dir, 'cache.db')) # file to use for pdict cache
log_file    = os.path.join(state_dir, 'webscraping.log') # default logging file

log_level = logging.INFO # logging level
default_encoding = 'utf-8'
default_headers =  {
    'Referer': '', 
    'Accept-Language': 'zh-CN,zh;q=0.9,sq;q=0.8,en;q=0.7',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
}
