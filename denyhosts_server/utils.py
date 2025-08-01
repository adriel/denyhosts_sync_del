# denyhosts sync server
# Copyright (C) 2015-2016 Jan-Pascal van Best <janpascal@vanbest.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import time
import ipaddr
import socket
import uuid

import gc
import psutil

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet import reactor, task

_hosts_busy = set()

@inlineCallbacks
def wait_and_lock_host(host):
    logging.debug("Attempting to lock host: {}".format(host))
    
    wait_start = time.time()
    waited = False
    
    try:
        while host in _hosts_busy:
            if not waited:  # Log only once when we start waiting
                logging.info("Host {} is busy, waiting for release".format(host))
                waited = True
            yield task.deferLater(reactor, 0.01, lambda _: 0, 0)
        
        if waited:
            wait_time = time.time() - wait_start
            logging.info("Host {} became available after {:.2f}s".format(host, wait_time))
            
        _hosts_busy.add(host)
        logging.debug("Successfully locked host: {}".format(host))
        
    except Exception as e:
        logging.error("Failed to lock host {}: {}".format(host, str(e)), exc_info=True)
        raise
    
    returnValue(0)

def unlock_host(host):
    try:
        _hosts_busy.remove(host)
        #logging.debug("host {} unlocked, {} blocked now".format(host, len(_hosts_busy)))
    except Exception as e:
        logging.debug("Exception in unlocking {}: {}".format(host, str(e)), exc_info=True)

def none_waiting():
    return len(_hosts_busy) == 0

def count_waiting():
    return len(_hosts_busy)

def is_valid_ip_address(ip_address):
    try:
        ip = ipaddr.IPAddress(ip_address)
    except:
        return False
    if (ip.is_reserved or ip.is_private or ip.is_loopback or
        ip.is_unspecified or ip.is_multicast or
        ip.is_link_local):
        return False
    return True

def getIP(d):
    """
    This method returns the first IP address string
    that responds as the given domain name
    """
    return socket.gethostbyname(d)

## generate Transactionid
def generateTrxId():
    return uuid.uuid4().hex

# utility classes for execution time monitoring
class TimerError(Exception):
    """A custom exception used to report errors in use of Timer class"""


class Timer:
    def __init__(self):
        self._start_time = None
        self._stop_time = None


    def start(self):
        """Start a new timer"""
        if self._start_time is not None:
            raise TimerError("Timer is running. Use .stop() to stop it")
        self._stop_time = None
        self._start_time = time.perf_counter()


    def stop(self):
        """Stop the timer, and report the elapsed time"""
        if self._start_time is None:
            raise TimerError("Timer is not running. Use .start() to start it")
        self._stop_time = time.perf_counter()

    def __str__(self):
        elapsed_time = self._stop_time - self._start_time
        self._start_time = None
        self._stop_time = None
        return "Elapsed time: {elapsed_time:0.4f} seconds"

    def getElapsed_time(self):
        elapsed_time = self._stop_time - self._start_time
        self._start_time = None
        self._stop_time = None
        return elapsed_time
    
    def getOngoing_time(self):
        ongoing_time = time.perf_counter() - self._start_time
        return ongoing_time

# Memory optimisation functions
def log_memory_usage(context=""):
    """Log current memory usage"""
    try:
        process = psutil.Process()
        memory_info = process.memory_info()
        logging.debug("Memory usage {}: RSS={:.2f}MB, VMS={:.2f}MB".format(
            context, memory_info.rss / 1024 / 1024, memory_info.vms / 1024 / 1024))
    except Exception as e:
        logging.debug("Could not get memory info: {}".format(e))

def force_garbage_collection():
    """Force garbage collection and log results"""
    before = gc.get_count()
    collected = gc.collect()
    after = gc.get_count()
    logging.debug("Garbage collection: collected {} objects, counts before: {}, after: {}".format(
        collected, before, after))

def periodic_memory_cleanup():
    """Periodic memory cleanup function"""
    log_memory_usage("before cleanup")
    force_garbage_collection()
    log_memory_usage("after cleanup")

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
