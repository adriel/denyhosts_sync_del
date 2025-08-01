#    denyhosts sync server
#    Copyright (C) 2015-2016 Jan-Pascal van Best <janpascal@vanbest.org>

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.

#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import configparser
import inspect
import logging
import os.path
import sys
import sqlite3

def _get(config, section, option, default=None):
    try:
        result = config.get(section, option)
    except configparser.NoOptionError:
        result = default
    return result

def _gethex(config, section, option, default=None):
    try:
        result = config.get(section, option)
    except configparser.NoOptionError:
        result = default
    if result is not None:
        result = bytes.fromhex(result)
    return result

def _getint(config, section, option, default=None):
    try:
        result = config.getint(section, option)
    except configparser.NoOptionError:
        result = default
    return result

def _getboolean(config, section, option, default=None):
    try:
        result = config.getboolean(section, option)
    except configparser.NoOptionError:
        result = default
    return result

def _getfloat(config, section, option, default=None):
    try:
        result = config.getfloat(section, option)
    except configparser.NoOptionError:
        result = default
    return result

def read_config(filename):
    global dbtype, dbparams
    global maintenance_interval, expiry_days, legacy_expiry_days
    global max_reported_crackers
    global max_processing_time_get_new_hosts
    global logfile
    global loglevel
    global xmlrpc_listen_port
    global legacy_server
    global legacy_frequency
    global legacy_threshold, legacy_resiliency
    global enable_debug_methods
    global stats_frequency
    global stats_resolve_hostnames
    global stats_listen_port
    global static_dir, graph_dir, template_dir
    global key_file, peers

    _config = configparser.ConfigParser()
    with open(filename, "r", encoding="utf-8") as f:
        _config.read_file(f)

    dbtype = _get(_config, "database", "type", "sqlite3")
    if dbtype not in ["sqlite3","MySQLdb"]:
        print("Database type {} not supported, exiting".format(dbtype))
        sys.exit()

    dbparams = {
        key: value 
        for (key,value) in _config.items("database") 
        if key != "type"
    }
    if dbtype=="sqlite3":
        dbparams["check_same_thread"] = False
        dbparams["detect_types"] = sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        dbparams["cp_max"] = 1
        if "database" not in dbparams:
            dbparams["database"] = "/var/lib/denyhosts-server/denyhosts.sqlite"
    # Memory-optimized database configuration section
    elif dbtype=="MySQLdb":
        dbparams["cp_reconnect"] = True
        # Additional MySQL performance settings
        dbparams["charset"] = _get(_config, "database", "charset", "utf8mb4")
        dbparams["use_unicode"] = _getboolean(_config, "database", "use_unicode", True)
        dbparams["autocommit"] = _getboolean(_config, "database", "autocommit", True)

        # OPTIMIZED: Reduced connection pool for lower memory usage
        dbparams["cp_max"] = _getint(_config, "database", "cp_max", 25)   # Reduced from 15
        dbparams["cp_min"] = _getint(_config, "database", "cp_min", 3)   # Reduced from 3

        # Faster timeouts for responsiveness
        dbparams["connect_timeout"] = _getint(_config, "database", "connect_timeout", 25)
        
        # Memory optimization settings
        dbparams["cp_noisy"] = _getboolean(_config, "database", "cp_noisy", False)  # Reduce logging overhead
        dbparams["cp_openfun"] = None  # Don't keep connection metadata
        
    if "cp_max" in dbparams:
        dbparams["cp_max"] = int(dbparams["cp_max"])
    if "cp_min" in dbparams:
        dbparams["cp_min"] = int(dbparams["cp_min"])
    if "port" in dbparams:
        dbparams["port"] = int(dbparams["port"])
    if "connect_timeout" in dbparams:
        dbparams["connect_timeout"] = int(dbparams["connect_timeout"])

    maintenance_interval = _getint(_config, "maintenance", "interval_seconds", 3600)
    expiry_days = _getfloat(_config, "maintenance", "expiry_days", 30)
    legacy_expiry_days = _getfloat(_config, "maintenance", "legacy_expiry_days", 30)

    max_reported_crackers = _getint(_config, "sync", "max_reported_crackers", 50)
    #That default value is set because in the client part the timeout is 30 seconds
    max_processing_time_get_new_hosts  = _getint(_config, "sync", "max_processing_time_get_new_hosts", 28)
    xmlrpc_listen_port = _getint(_config, "sync", "listen_port", 9911)
    enable_debug_methods = _getboolean(_config, "sync", "enable_debug_methods", False)
    legacy_server = _get(_config, "sync", "legacy_server", None)
    legacy_frequency = _getint(_config, "sync", "legacy_frequency", 300)
    legacy_threshold = _getint(_config, "sync", "legacy_threshold", 10)
    legacy_resiliency = _getint(_config, "sync", "legacy_resiliency", 10800)

    logfile = _get(_config, "logging", "logfile", "/var/log/denyhosts-server/denyhosts-server.log")
    loglevel = _get(_config, "logging", "loglevel", "INFO")
    try:
        loglevel = int(loglevel)
    except ValueError:
        try:
            loglevel = logging.__dict__[loglevel]
        except KeyError:
            print("Illegal log level {}".format(loglevel))
            loglevel = logging.INFO

    stats_frequency = _getint(_config, "stats", "update_frequency", 600)
    package_dir =  os.path.dirname(os.path.dirname(inspect.getsourcefile(read_config)))
    static_dir = _get(_config, "stats", "static_dir", 
        os.path.join( 
            package_dir,
            "static"))
    graph_dir = _get(_config, "stats", "graph_dir", os.path.join(static_dir, "graph"))
    template_dir = _get(_config, "stats", "template_dir", os.path.join(package_dir, "template"))
    stats_resolve_hostnames = _getboolean(_config, "stats", "resolve_hostnames", True)
    stats_listen_port = _getint(_config, "stats", "listen_port", 9911)

    key_file = _get(_config, "peering", "key_file", os.path.join(package_dir, "private.key"))

    peers = {}
    for item in _config.items("peering"):
        if item[0].startswith("peer_") and item[0].endswith("_url"):
            url = item[1]
            key_key = item[0].replace("_url", "_key")
            key = _gethex(_config, "peering", key_key);
            peers[url] = key
