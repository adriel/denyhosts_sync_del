#    denyhosts sync server
#    Copyright (C) 2015-2017 Jan-Pascal van Best <janpascal@vanbest.org>

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

import time
import logging
import random

from twisted.web import server, xmlrpc, error
from twisted.web.resource import Resource
from twisted.web.xmlrpc import withRequest
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet import reactor
from twisted.python import log

from . import models
from .models import Cracker, Report
from . import config
from . import controllers
from . import utils
from . import stats
from . import peering

class Server(xmlrpc.XMLRPC):
    """
    An example object to be published.
    """

    @withRequest
    @inlineCallbacks
    # DenyHosts clients call this to report new attacking IPs TO the server
    def xmlrpc_add_hosts(self, request, hosts):
        # Identify the transaction for logging correlation
        trxId = utils.generateTrxId()

        # Timer to monitor the trx duration
        trx_timer = utils.Timer()
        trx_timer.start()

        try:
            x_real_ip = request.requestHeaders.getRawHeaders("X-Real-IP")
            remote_ip = x_real_ip[0] if x_real_ip else request.getClientIP()
            now = int(time.time())

            # Cleanup of the input as I have observed some dupe inputs creating overload on the db side
            hosts_uniq = sorted(set(hosts))
            nb_prune = len(hosts) - len(hosts_uniq)
            logging.info("[TrxId:{}] add_hosts({}) compacted by {} from {}".format(trxId, hosts_uniq, nb_prune, remote_ip))

            yield controllers.handle_report_from_client(remote_ip, now, hosts_uniq, trxId)

            # Send update to peers - handle peering errors gracefully
            try:
                yield peering.send_update(remote_ip, now, hosts_uniq)
            except Exception as e:
                # Log peering errors but don't fail the main operation
                logging.warning("[TrxId:{}] Error sending update to peers: {}".format(trxId, str(e)))
                # Continue processing - peering failure shouldn't fail the client request

        except xmlrpc.Fault as e:
            # Re-raise xmlrpc.Fault without modification
            raise e
        except Exception as e:
            log.err(e, f"[TrxId:{trxId}] Exception in add_hosts: {e}")
            raise xmlrpc.Fault(104, "[TrxId:{}] Error adding hosts: {}".format(trxId, str(e)))
        finally:
            # Always stop the timer regardless of success or failure
            trx_timer.stop()
            elapsed_time = trx_timer.getElapsed_time()
            logging.info("[TrxId:{0}] add_hosts completed in {1:.3f} seconds".format(trxId, elapsed_time))

        returnValue(0)

    @withRequest
    @inlineCallbacks
    # DenyHosts clients call this to get attacking IPs FROM the server
    def xmlrpc_get_new_hosts(self, request, timestamp, threshold, hosts_added, resiliency):
        # Identify the transaction for logging correlation
        trxId= utils.generateTrxId()

        # Timer to monitor the trx duration
        trx_timer = utils.Timer()
        trx_timer.start()

        try:
            x_real_ip = request.requestHeaders.getRawHeaders("X-Real-IP")
            remote_ip = x_real_ip[0] if x_real_ip else request.getClientIP()

            logging.info("[TrxId:{}] get_new_hosts({},{},{},{}) from {}".format(trxId, timestamp, threshold, 
                hosts_added, resiliency, remote_ip))
            try:
                timestamp = int(timestamp)
                threshold = int(threshold)
                resiliency = int(resiliency)
            except Exception as e:
                logging.warning("[TrxId:{}] Illegal arguments to get_new_hosts from client {}: {}".format(trxId, remote_ip, str(e)))
                raise xmlrpc.Fault(102, "[TrxId:{}] Illegal parameters.".format(trxId))

            now = int(time.time()) 
            # refuse timestamps from the future
            if timestamp > now:
                logging.warning("[TrxId:{}] Illegal timestamp to get_new_hosts from client {}".format(trxId, remote_ip))
                raise xmlrpc.Fault(103, "[TrxId:{}] Illegal timestamp.".format(trxId))

            for host in hosts_added:
                if not utils.is_valid_ip_address(host):
                    logging.warning("[TrxId:{}] Illegal host ip address {}".format(trxId, host))
                    raise xmlrpc.Fault(101, "[TrxId:{}] Illegal IP address \"{}\".".format(trxId, host))

            # TODO: maybe refuse timestamp from far past because it will 
            # cause much work? OTOH, denyhosts will use timestamp=0 for 
            # the first run!
            # ### Not currently used, as server handles curret load fine
            # ### Plus, the db only goes back to 1 year of data.
            # # Check for timestamps from far past that could cause excessive work
            # # Allow timestamp=0 for legitimate first-run scenarios
            # # Reject timestamps older than a reasonable threshold (e.g., 1 year)
            # max_age_seconds = 365 * 24 * 3600  # 1 year
            # min_allowed_timestamp = now - max_age_seconds
            
            # if timestamp != 0 and timestamp < min_allowed_timestamp:
            #     age_days = (now - timestamp) // (24 * 3600)
            #     logging.warning("[TrxId:{}] Timestamp too old from client {}: {} days old (timestamp: {})".format(
            #         trxId, remote_ip, age_days, timestamp))
            #     raise xmlrpc.Fault(108, "[TrxId:{}] Timestamp too old ({} days). Use timestamp=0 for initial sync.".format(
            #         trxId, age_days))
            # elif timestamp == 0:
            #     logging.info("[TrxId:{}] Initial sync request (timestamp=0) from {}".format(trxId, remote_ip))
            # else:
            #     age_hours = (now - timestamp) // 3600
            #     logging.debug("[TrxId:{}] Normal sync request from {} (age: {} hours)".format(trxId, remote_ip, age_hours))
            
            # Check if client IP is a known cracker
            if utils.is_valid_ip_address(remote_ip):
                client_cracker = yield controllers.get_cracker(remote_ip)
                if client_cracker is not None:
                    # Client IP is a known cracker - decide how to handle this
                    # Option 1: Reject the request entirely
                    logging.warning("[TrxId:{}] Request from known cracker IP {} - rejecting request".format(trxId, remote_ip))
                    raise xmlrpc.Fault(107, "[TrxId:{}] Request from known malicious IP address.".format(trxId))
                    
                    # Option 2: Log but allow (commented out alternative)
                    # logging.warning("[TrxId:{}] Request from known cracker IP {} - allowing but logging".format(trxId, remote_ip))
                    
                    # Option 3: Return empty result (commented out alternative)
                    # logging.warning("[TrxId:{}] Request from known cracker IP {} - returning empty result".format(trxId, remote_ip))
                    # result = {'timestamp': str(int(time.time())), 'hosts': []}
                    # returnValue(result)
                else:
                    logging.debug("[TrxId:{}] Client IP {} is not a known cracker - proceeding".format(trxId, remote_ip))
            else:
                logging.debug("[TrxId:{}] Client IP {} is not a valid public IP - proceeding".format(trxId, remote_ip))

            result = {}
            result['timestamp'] = str(int(time.time()))
            result['hosts'] = yield controllers.get_qualifying_crackers(
                    threshold, resiliency, timestamp, 
                    config.max_reported_crackers, set(hosts_added), trxId)
            logging.debug("[TrxId:{}] get_new_hosts returning: {}".format(trxId, result))
            
        except xmlrpc.Fault as e:
            raise e
        except Exception as e:
            log.err(_why="[TrxId:{}] Exception in xmlrpc_get_new_hosts".format(trxId))
            raise xmlrpc.Fault(105, "[TrxId:{}] Error in get_new_hosts: {}".format(trxId, str(e)))
        finally:
            # Always stop the timer and log transaction data regardless of success or failure
            trx_timer.stop()
            elapsed_time = trx_timer.getElapsed_time()
            # Only log host count on success (result will be defined)
            try:
                host_count = len(result['hosts']) if 'result' in locals() and result else 0
                logging.info("[TrxId:{0}] get_new_hosts completed in {1:.3f} seconds returning {2} hosts".format(
                    trxId, elapsed_time, host_count))
            # If result is not available (due to exception), just log the timing
            except Exception as e:
                logging.warning("[TrxId:{}] Logging hosts failed: {} — falling back to timing log only".format(trxId, str(e)))
                logging.info("[TrxId:{0}] get_new_hosts completed in {1:.3f} seconds (with error)".format(trxId, elapsed_time))

        returnValue(result)

    @withRequest
    def xmlrpc_version_report(self, request, version_info):
        """
        Handle version reporting from denyhosts clients.
        This method logs the client version information for monitoring purposes.
        """
        # Identify the transaction for logging correlation
        trxId = utils.generateTrxId()

        try:
            x_real_ip = request.requestHeaders.getRawHeaders("X-Real-IP")
            remote_ip = x_real_ip[0] if x_real_ip else request.getClientIP()

            # Parse and log version info more clearly
            if isinstance(version_info, list) and len(version_info) >= 2:
                denyhosts_version = version_info[0]
                sync_version = version_info[1] 
                logging.info("[TrxId:{}] version_report from {}: Python v{}, Denyhosts v{}".format(
                    trxId, remote_ip, denyhosts_version, sync_version))
            else:
                logging.info("[TrxId:{}] version_report from {}: {}".format(trxId, remote_ip, version_info))

            # You can optionally store this information in the database
            # or perform any other processing you need

            # Return success (0) or any other appropriate response
            return 0

        except Exception as e:
            logging.error("[TrxId:{}] Error in version_report: {}".format(trxId, str(e)))
            raise xmlrpc.Fault(106, "[TrxId:{}] Error processing version report: {}".format(trxId, str(e)))
        
class WebResource(Resource):
    #isLeaf = True

    def getChild(self, name, request):
        if name == b'':
            return self
        return Resource.getChild(self, name, request)

    def render_GET(self, request):
        logging.debug("GET({})".format(request))
        request.setHeader("Content-Type", "text/html; charset=utf-8")
        def done(result):
            if result is None:
                request.write("<h1>An error has occurred</h1>")
            else:
                request.write(result.encode('utf-8'))
            request.finish()
        def fail(err):
            request.processingFailed(err)
        stats.render_stats().addCallbacks(done, fail)
        return server.NOT_DONE_YET

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4