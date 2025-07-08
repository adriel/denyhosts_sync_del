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
from xmlrpc.client import ServerProxy

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.threads  import deferToThread

from . import config
from . import database
from . import models
from .models import Cracker, Report, Legacy
from . import utils

def get_cracker(ip_address):
    return Cracker.find(where=["ip_address=?",ip_address], limit=1)

@inlineCallbacks
def handle_report_from_client(client_ip, timestamp, hosts, trxId=None):
    utils.log_memory_usage("start of handle_report_from_client")

    try:
        test_result = yield database.run_query("SELECT 1")
        logging.info("[TrxId:{}] Database connection test passed".format(trxId))
    except Exception as e:
        logging.error("[TrxId:{}] Database connection failed: {}".format(trxId, str(e)))
        raise

    for cracker_ip in hosts:
        validIP = False
        if not utils.is_valid_ip_address(cracker_ip):
            try:
                cracker_ip_tentative = utils.getIP(cracker_ip)
                logging.debug("[TrxId:{}] Tried to convert {} to {}".format(trxId, cracker_ip, cracker_ip_tentative))

                if not utils.is_valid_ip_address(cracker_ip_tentative):
                    logging.warning("[TrxId:{}] Invalid IP address {} from {} after conversion - Ignored".format(trxId, cracker_ip, client_ip))
                    continue  # Skip this IP and move to next one
                else:
                    validIP = True
                    logging.info("[TrxId:{}] Illegal host IP converted {} to {} from {}".format(trxId, cracker_ip, cracker_ip_tentative, client_ip))
                    cracker_ip = cracker_ip_tentative

            except (ValueError, TypeError, OSError) as e:
                # Handle specific IP conversion errors
                logging.warning("[TrxId:{}] Failed to convert IP {} from {}: {} - Ignored".format(trxId, cracker_ip, client_ip, str(e)))
                continue  # Skip this IP and move to next one

            except Exception as e:
                # Log unexpected errors but don't let them crash the processing
                logging.error("[TrxId:{}] Unexpected error processing IP {} from {}: {} - Ignored".format(trxId, cracker_ip, client_ip, str(e)))
                continue  # Skip this IP and move to next one
        else:
            validIP = True

        if validIP:
            logging.debug("[TrxId:{}] Adding report for {} from {}".format(trxId, cracker_ip, client_ip))
            yield utils.wait_and_lock_host(cracker_ip)
            try:
                cracker = yield Cracker.find(where=['ip_address=?', cracker_ip], limit=1)
                if cracker is None:
                    cracker = Cracker(ip_address=cracker_ip, first_time=timestamp,
                        latest_time=timestamp, resiliency=0, total_reports=0, current_reports=0)
                    yield cracker.save()
                yield add_report_to_cracker(cracker, client_ip, when=timestamp, trxId=trxId)
            finally:
                utils.unlock_host(cracker_ip)
            logging.debug("[TrxId:{}] Done adding report for {} from {}".format(trxId, cracker_ip,client_ip))

    # Add cleanup at the end
    if len(hosts) > 100:  # Only for large batches
        utils.force_garbage_collection()

    utils.log_memory_usage("end of handle_report_from_client")

# Note: lock cracker IP first!
# Report merging algorithm by Anne Bezemer, see 
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=622697
@inlineCallbacks
def add_report_to_cracker(cracker, client_ip, when=None, trxId=None):
    if when is None:
        when = int(time.time())

    reports = yield Report.find(
        where=["cracker_id=? AND ip_address=?", cracker.id, client_ip], 
        orderby='latest_report_time ASC'
    )
    if len(reports) == 0:
        # First report from this IP for this cracker
        report = Report(ip_address=client_ip, first_report_time=when, latest_report_time=when)
        yield report.save()
        yield report.cracker.set(cracker)
        cracker.current_reports += 1
    elif len(reports) == 1:
        report = reports[0]
        # Check if 24 hours have passed since the last report
        if when > report.latest_report_time + 24*3600:
            # Create second report
            report = Report(ip_address=client_ip, first_report_time=when, latest_report_time=when)
            yield report.save()
            yield report.cracker.set(cracker)
            cracker.current_reports += 1
        else:
            # Update existing report's latest time
            report.latest_report_time = when
            yield report.save()
    elif len(reports) == 2:
        latest_report = reports[1]  # Most recent report
        # Add third report after again 24 hours
        if when > latest_report.latest_report_time + 24*3600:
            # Create third report
            report = Report(ip_address=client_ip, first_report_time=when, latest_report_time=when)
            yield report.save()
            yield report.cracker.set(cracker)
            cracker.current_reports += 1
        else:
            # Update existing latest report's time
            latest_report.latest_report_time = when
            yield latest_report.save()
    else:
        # 3 or more reports - just update the latest one
        latest_report = reports[-1]
        latest_report.latest_report_time = when
        yield latest_report.save()
    
    # Update cracker statistics
    cracker.total_reports += 1
    cracker.latest_time = when
    cracker.resiliency = when - cracker.first_time
    yield cracker.save()

@inlineCallbacks
def get_qualifying_crackers(min_reports, min_resilience, previous_timestamp,
        max_crackers, latest_added_hosts, trxId=None):

    # Start measurement of elapsed time
    aTimer = utils.Timer()
    aTimer.start()

    # If min_reports is 1, then resiliency value must be discarded
    if min_reports == 1:
        min_resilience = 0
    
    result = []
    processed_count = 0
    batch_size = 100  # Process in small batches to avoid memory issues
    offset = 0
    
    while len(result) < max_crackers:
        # Get crackers in batches to avoid loading everything into memory
        batch_crackers = yield database.run_query("""
            SELECT DISTINCT 
                c.id, c.ip_address, c.first_time, c.latest_time, 
                c.total_reports, c.current_reports, c.resiliency
            FROM crackers c 
            WHERE (c.current_reports >= ?)
                AND (c.resiliency >= ?)
                AND (c.latest_time >= ?)
            ORDER BY c.first_time DESC
            LIMIT ? OFFSET ?
            """, min_reports, min_resilience, previous_timestamp, batch_size, offset)
        
        if not batch_crackers:
            break  # No more crackers to process
            
        # Process each cracker in the batch
        for cracker_row in batch_crackers:
            processed_count += 1
            cracker_id = cracker_row[0]
            cracker_ip = cracker_row[1]
            
            if cracker_ip in latest_added_hosts:
                logging.debug("[TrxId:{}] Skipping {}, just reported by client".format(trxId, cracker_ip))
                continue

            # Create cracker object
            cracker = Cracker(id=cracker_row[0], ip_address=cracker_row[1], 
                             first_time=cracker_row[2], latest_time=cracker_row[3], 
                             total_reports=cracker_row[4], current_reports=cracker_row[5], 
                             resiliency=cracker_row[6])
            
            logging.debug("[TrxId:{}] Examining ".format(trxId) + str(cracker))

            # Get reports for this specific cracker only
            reports = yield database.run_query("""
                SELECT first_report_time, latest_report_time, ip_address
                FROM reports 
                WHERE cracker_id = ?
                ORDER BY first_report_time ASC
                """, cracker_id)
            
            # Convert to dict format for compatibility
            reports_data = [
                {
                    'first_report_time': r[0],
                    'latest_report_time': r[1],
                    'ip_address': r[2]
                } for r in reports
            ]
            
            logging.debug("[TrxId:{}] r[m-1].first_report_time={}, previous_timestamp={}, nb={}".format(
                trxId, reports_data[min_reports-1]['first_report_time'] if len(reports_data) >= min_reports else 'N/A', 
                previous_timestamp, len(reports_data)))
            
            # Same logic as original for conditions (c) and (d)
            if (len(reports_data) >= min_reports and 
                reports_data[min_reports-1]['first_report_time'] >= previous_timestamp): 
                # condition (c) satisfied
                logging.debug("[TrxId:{}] condition (c) satisfied - Appending {}".format(trxId, cracker.ip_address))
                result.append(cracker.ip_address)
            else:
                logging.debug("[TrxId:{}] checking condition (d)...".format(trxId))
                satisfied = False
                for report in reports_data:
                    if (not satisfied and 
                        report['latest_report_time'] >= previous_timestamp and
                        report['latest_report_time'] - cracker.first_time >= min_resilience):
                        logging.debug("[TrxId:{}]     d1".format(trxId))
                        satisfied = True
                    if (report['latest_report_time'] <= previous_timestamp and 
                        report['latest_report_time'] - cracker.first_time >= min_resilience):
                        logging.debug("[TrxId:{}]     d2 failed".format(trxId))
                        satisfied = False
                        break
                if satisfied:
                    logging.debug("[TrxId:{}] condition (d) satisfied - Appending {}".format(trxId, cracker.ip_address))
                    result.append(cracker.ip_address)
                else:
                    logging.debug("[TrxId:{}]     skipping {}".format(trxId, cracker.ip_address))
            
            # Clear references to help garbage collection
            del cracker
            del reports_data
            
            # Check if processing should stop due to time limit or result count limit
            elapsed_time = aTimer.getOngoing_time()
            time_limit_reached = elapsed_time > config.max_processing_time_get_new_hosts
            count_limit_reached = len(result) >= max_crackers

            if time_limit_reached or count_limit_reached:
                reasons = []
                if time_limit_reached:
                    reasons.append(f"time limit ({elapsed_time:.2f}s >= {config.max_processing_time_get_new_hosts:.2f}s)")
                if count_limit_reached:
                    reasons.append(f"count limit ({len(result)} >= {max_crackers})")

                logging.info("[TrxId:{}] Breaking due to: {}. Processed {} crackers, found {} qualifying hosts".format(
                    trxId, " and ".join(reasons), processed_count, len(result)))
                break
        
        # Break outer loop if we broke inner loop
        if len(result) >= max_crackers or aTimer.getOngoing_time() > config.max_processing_time_get_new_hosts:
            break
            
        offset += batch_size
    
    logging.debug("[TrxId:{}] Completed processing {} crackers, returning {} hosts".format(
        trxId, processed_count, len(result)))

    if len(result) < max_crackers:
        # Add results from legacy server
        extras = yield Legacy.find(where=["retrieved_time>?", previous_timestamp],
            orderby="retrieved_time DESC", limit=max_crackers-len(result))
        result = result + [extra.ip_address for extra in extras]

    logging.debug("[TrxId:{}] Returning {} hosts".format(trxId, len(result)))
    returnValue(result)
# Periodical database maintenance
# From algorithm by Anne Bezemer, see https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=622697
# Expiry/maintenance every hour/day:
#   remove reports with .latestreporttime older than (for example) 1 month
#     and only update cracker.currentreports
#   remove reports that were reported by what we now "reliably" know to
#     be crackers themselves
#   remove crackers that have no reports left

# TODO remove reports by identified crackers

@inlineCallbacks
def perform_maintenance(limit = None, legacy_limit = None):
    logging.info("Starting maintenance job...")
    try:
        if limit is None:
            now = int(time.time())
            limit = now - config.expiry_days * 24 * 3600

        if legacy_limit is None:
            now = int(time.time())
            legacy_limit = now - config.legacy_expiry_days * 24 * 3600

        reports_deleted = 0
        crackers_deleted = 0
        legacy_deleted = 0

        batch_size = 1000
    
        while True:
            old_reports = yield Report.find(where=["latest_report_time<?", limit], limit=batch_size)
            if len(old_reports) == 0:
                break
            logging.info("Removing batch of {} old reports".format(len(old_reports)))
            for report in old_reports:
                cracker = yield report.cracker.get()
                yield utils.wait_and_lock_host(cracker.ip_address)
                try:
                    logging.info("Maintenance: removing report from {} for cracker {}".format(report.ip_address, cracker.ip_address))
                    yield report.cracker.clear()
                    yield report.delete()
                    reports_deleted += 1

                    current_reports = yield cracker.reports.get(group='ip_address')
                    cracker.current_reports = len(current_reports)
                    yield cracker.save()

                    if cracker.current_reports == 0:
                        logging.info("Maintenance: removing cracker {}".format(cracker.ip_address))
                        yield cracker.delete()
                        crackers_deleted += 1
                finally:
                    utils.unlock_host(cracker.ip_address)
                logging.info("Maintenance on report from {} for cracker {} done".format(report.ip_address, cracker.ip_address))
        
        logging.info("Report cleanup complete, starting legacy cleanup...")
        legacy_reports = yield Legacy.find(where=["retrieved_time<?", legacy_limit])
        if legacy_reports is not None:
            for legacy in legacy_reports:
                yield legacy.delete()
                legacy_deleted += 1
        
        logging.info("Legacy cleanup complete")
        logging.info("Done maintenance job")
        logging.info("Expired {} reports and {} hosts, plus {} hosts from the legacy list".format(reports_deleted, crackers_deleted, legacy_deleted))
    except Exception as e:
        logging.error("Maintenance job failed with exception: {}".format(e))
        logging.exception("Full traceback:")
        raise

    returnValue(0)

@inlineCallbacks
def download_from_legacy_server():
    if config.legacy_server is None or config.legacy_server == "":
        returnValue(0)

    logging.info("Downloading hosts from legacy server...")
    rows = yield database.run_query('SELECT `value` FROM info WHERE `key`="last_legacy_sync"')
    last_legacy_sync_time = int(rows[0][0])

    try:
        server = yield deferToThread(ServerProxy, config.legacy_server)

        response = yield deferToThread(server.get_new_hosts, 
            last_legacy_sync_time, config.legacy_threshold, [],
            config.legacy_resiliency)
        try:
            last_legacy_sync_time = int(response["timestamp"])
        except:
            logging.error("Illegal timestamp {} from legacy server".format(response["timestamp"]))
        #Registry.DBPOOL.runOperation('UPDATE info SET `value`=%s WHERE `key`="last_legacy_sync"', (str(last_legacy_sync_time),))
        database.run_operation('UPDATE info SET `value`=? WHERE `key`="last_legacy_sync"', str(last_legacy_sync_time))
        now = int(time.time())
        logging.debug("Got {} hosts from legacy server".format(len(response["hosts"])))
        for host in response["hosts"]:
            legacy = yield Legacy.find(where=["ip_address=?",host], limit=1)
            if legacy is None:
                logging.debug("New host from legacy server: {}".format(host))
                legacy = Legacy(ip_address=host, retrieved_time=now)
            else:
                logging.debug("Known host from legacy server: {}".format(host))
                legacy.retrieved_time = now
            yield legacy.save()
    except Exception as e:
        logging.error("Error retrieving info from legacy server: {}".format(e))

    logging.info("Done downloading hosts from legacy server.")
    returnValue(0)

@inlineCallbacks
def purge_legacy_addresses():
    yield database.run_truncate_query('legacy')
    yield database.run_query('UPDATE info SET `value`=0 WHERE `key`="last_legacy_sync"')
    returnValue(0)

@inlineCallbacks
def purge_reported_addresses():
    yield database.run_truncate_query('crackers')
    yield database.run_truncate_query('reports')
    returnValue(0)

@inlineCallbacks
def purge_ip(ip):
    yield database.run_query("""DELETE FROM reports
        WHERE cracker_id IN (
            SELECT id FROM crackers WHERE ip_address=?
            )""", ip)
    yield database.run_query("DELETE FROM crackers WHERE ip_address=?", ip)
    yield database.run_query("DELETE FROM legacy WHERE ip_address=?", ip)
    returnValue(0)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
