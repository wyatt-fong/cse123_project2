"""
CSE 123 autograder library.
(Adapted from "cse123_test_base.py")

Author      : Adyanth Hosavalike (ahosavalike@ucsd.edu)
Author      : Rajdeep Das (r4das@ucsd.edu)
Offering    : Spring 2023
"""

import pexpect
import unittest
import os
import re
import subprocess
import threading
import time
import shutil
import traceback
import logging
import warnings
import contextlib
import io
import sys

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from scapy.all import sendp, sniff, Ether, ARP, ICMP, IP, IPv6, TCP, UDP
from queue import Queue, Empty

from project_base.lab import *

@contextlib.contextmanager
def nostdout():
    tso = sys.stdout
    sys.stdout = io.StringIO()
    yield
    sys.stdout = tso

class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, new_path):
        self.new_path = os.path.expanduser(new_path)

    def __enter__(self):
        self.saved_path = os.getcwd()
        if self.saved_path != self.new_path:
            os.chdir(self.new_path)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.saved_path)

"""
Base unit test class for all tests. Contains environment setup and test utility functions.
"""
class CSE123TestBase(unittest.TestCase):
    TEST_DIR = os.path.dirname(os.path.abspath(__file__))
    LOCK_FILE = os.path.join(TEST_DIR, 'test.lock')

    SUBMISSION_DIR = os.path.dirname(TEST_DIR)
    VNET_BASE_PATH = "/project-base/"

    NODES = ('server1', 'server2', 'client')

    DEFAULT_NODE = 'client'

    def buildSRSolution(self):
        logging.info("Building solution ... ")
        with cd(self.SUBMISSION_DIR):
            with open( os.path.join(self.SUBMISSION_DIR, 'test_make_stderr.log'), 'w') as logf_stdout, \
                open( os.path.join(self.SUBMISSION_DIR, 'test_make_stdout.log'), 'w') as logf_stderr:
                try:
                    assert(os.system("make clean > /dev/null") == 0)
                    subprocess.check_call(
                        "make",
                        stdout=logf_stdout,
                        stderr=logf_stderr
                    )
                except AssertionError:
                    logging.info("Make clean failed!")
                except subprocess.CalledProcessError:
                    logging.info("Solution build failed!")
                    logging.info(traceback.format_exc())
                    return False
        return True

    def cleanupEnvironment(self):
        os.system("pkill -9 sr")
        os.system("pkill -9 python2.7")
        os.system("mn -c 2> /dev/null")
        if os.path.exists(self.LOCK_FILE):
            print("Cleaning up ... ")
            os.remove(self.LOCK_FILE)

    def _peer_intf(self, host):
        link = host.defaultIntf().link
        return link.intf1 if link.intf1.node != host else link.intf2

    def _host_info(self, host_name, default_ip, default_gw):
        host = self.mininet.get(host_name)
        peer_intf = self._peer_intf(host)
        peer_node = peer_intf.node
        host_ip = IP_SETTING.get(host_name, default_ip)
        gw_ip = IP_SETTING.get(peer_intf.name, default_gw)

        return {
            "ip": host_ip,
            "gw": gw_ip,
            "m": host,
            "mac": host.MAC(),
            "gwmac": peer_node.MAC(intf=peer_intf.name),
            "gw_node": peer_node.name,
            "gw_intf": peer_intf.name,
        }

    def _host_defaults(self, pa2b):
        if pa2b:
            return {
                "client": ("192.168.1.2", "192.168.1.1"),
                "server1": ("192.168.2.2", "192.168.2.1"),
                "server2": ("192.168.3.2", "192.168.3.1"),
            }
        return {
            "client": ("10.0.1.100", "10.0.1.1"),
            "server1": ("192.168.2.2", "192.168.2.1"),
            "server2": ("172.64.3.10", "172.64.3.1"),
        }

    def _apply_pa2b_host_routes(self):
        for host in [self.client, self.server1, self.server2]:
            host["m"].cmd("ip route del 192.0.0.0/8 2>/dev/null")
            host["m"].cmd("ip route replace default via {}".format(host["gw"]))
            host["m"].cmd("arp -s {} {}".format(host["gw"], host["gwmac"]))

    def _start_router(self, router_path, args, log_name):
        log = open(os.path.join(self.SUBMISSION_DIR, log_name), 'w')
        router = pexpect.spawn(
            router_path,
            args,
            logfile=log,
            encoding="utf-8"
        )
        router.expect('<-- Ready to process packets -->', timeout=15)
        self.router_logs.append(log)
        self.routers.append(router)
        return router

    def _router_rtable_path(self, router_rtable):
        rtables_path = os.path.join("rtables", router_rtable)
        if os.path.exists(os.path.join(self.SUBMISSION_DIR, rtables_path)):
            return rtables_path
        if os.path.exists(os.path.join(self.SUBMISSION_DIR, router_rtable)):
            return router_rtable
        raise AssertionError(
            "Missing routing table {}. Copy PA2b rtables with: "
            "cp /project-base/rtable* rtables/".format(router_rtable)
        )

    def setUpEnvironment(self, rtable='rtable', build=True, debug=False,
                         manual_sr=False, pa2b=False, router_specs=None):

        global IPBASE, IP_SETTING

        assert(self.VNET_BASE_PATH is not None)
        assert(self.SUBMISSION_DIR is not None)

        self.cleanupEnvironment()

        with open(self.LOCK_FILE, 'w') as f:
            # pids = str(subprocess.check_output("ps -e | grep python | cut -f2 -d' '", shell=True)).splitlines()
            # f.write(",".join(pids))
            f.write("\n")
            f.close()


        self.ROUTING_TABLE = os.path.join(self.SUBMISSION_DIR, "rtables", rtable)
        shutil.copyfile(self.ROUTING_TABLE, os.path.join(self.SUBMISSION_DIR, "rtable"))

        self.pox = None
        self.mininet = None
        self.router = None
        self.routers = []
        self.router_logs = []

        pox_path = os.path.join(self.VNET_BASE_PATH, 'pox', 'pox.py')
        os.environ["PYTHONPATH"] = os.path.join(self.VNET_BASE_PATH, 'pox_module')
        router_path = os.path.join(self.SUBMISSION_DIR, 'sr')

        if build:
            self.assertTrue(self.buildSRSolution())

        with cd(self.VNET_BASE_PATH):
            self.pox_log = open(os.path.join(self.SUBMISSION_DIR, 'test_pox.log'), 'w')
            self.pox = pexpect.spawn(
                pox_path,
                args=['--verbose', 'ofhandler', 'srhandler', "openflow.of_01", "--port=6653"],
                logfile=self.pox_log,
                encoding="utf-8"
            )
            self.pox.expect('DEBUG:openflow.of_01:Listening on 0.0.0.0:6653')
            logging.info("POX started.")
            stophttp()
            with warnings.catch_warnings(), nostdout():
                warnings.simplefilter("ignore")
                
                get_ip_setting()
                topo = CS144Topo()
                # Gives warning even after ignore
                self.mininet = Mininet( topo=topo, controller=RemoteController, ipBase=IPBASE )
                self.mininet.start()
            server1, server2, client = self.mininet.get( 'server1', 'server2', 'client')
            s1intf = server1.defaultIntf()
            s2intf = server2.defaultIntf()
            clintf = client.defaultIntf()
            logging.info('Lab:')
            host_defaults = self._host_defaults(pa2b)
            host_prefix = 24 if pa2b else 8
            if pa2b:
                for host in server1, server2, client:
                    host.cmd("ip addr flush dev {}".format(host.defaultIntf().name))
            s1intf.setIP('%s/%d' % (
                IP_SETTING.get('server1', host_defaults["server1"][0]),
                host_prefix))
            s2intf.setIP('%s/%d' % (
                IP_SETTING.get('server2', host_defaults["server2"][0]),
                host_prefix))
            clintf.setIP('%s/%d' % (
                IP_SETTING.get('client', host_defaults["client"][0]),
                host_prefix))

            self.client = self._host_info("client", *host_defaults["client"])
            self.server1 = self._host_info("server1", *host_defaults["server1"])
            self.server2 = self._host_info("server2", *host_defaults["server2"])
            self.gateways = list(map(lambda x: x["gw"], [self.client, self.server1, self.server2]))

            if pa2b:
                self._apply_pa2b_host_routes()
            else:
                with nostdout():
                    for host in server1, server2, client:
                        set_default_route(host)

            starthttp( server1 )
            starthttp( server2 )
            self.pox.expect('.*srhandler:SRServerListener catch RouterInfo even.*')
            logging.info("Mininet started.")

        with cd(self.SUBMISSION_DIR):
            if manual_sr:
                input("Start router now and hit enter:")
            else:
                if pa2b:
                    if router_specs is None:
                        router_specs = [
                            ("sw1", "rtable1"),
                            ("sw2", "rtable2"),
                            ("sw3", "rtable3"),
                            ("sw4", "rtable4"),
                        ]

                    for index, (vhost, router_rtable) in enumerate(router_specs, 1):
                        args = [
                            "-l", "test{}.pcap".format(index),
                            "-v", vhost,
                            "-r", self._router_rtable_path(router_rtable),
                        ]
                        self._start_router(router_path, args,
                                           "test_sr_{}.log".format(vhost))
                    self.router = self.routers[0] if self.routers else None
                    logging.info("PA2b routers started.")
                else:
                    self.router = self._start_router(
                        router_path,
                        ["-l", "test.pcap"],
                        "test_sr.log"
                    )
                    logging.info("Router started.")

        self.pcap_stream_client = PacketTest(self._peer_intf(client).name, client, debug=debug)
        self.pcap_stream_server1 = PacketTest(self._peer_intf(server1).name, server1, debug=debug)
        self.pcap_stream_server2 = PacketTest(self._peer_intf(server2).name, server2, debug=debug)
        self.pcap_stream_client.run()
        self.pcap_stream_server1.run()
        self.pcap_stream_server2.run()

    def tearDownEnvironment(self):
        stophttp()

        self.pcap_stream_client.stop()
        self.pcap_stream_server1.stop()
        self.pcap_stream_server2.stop()

        for router in self.routers:
            if not router.terminate(force=True):
                print("Could not stop router")
            router.close()

        for router_log in self.router_logs:
            router_log.flush()
            router_log.close()

        if not self.pox.terminate(force=True):
            print("Could not stop pox")
        self.pox.close()
        self.pox_log.flush()
        self.pox_log.close()
        
        self.mininet.stop()
        
        os.remove(self.LOCK_FILE)

    def clearPcapBuffers(self):
        self.pcap_stream_client.clear()
        self.pcap_stream_server1.clear()
        self.pcap_stream_server2.clear()

    def fetchPcapBuffers(self):
        buffers = {
            'client'    : self.pcap_stream_client.fetch(),
            'server1'   : self.pcap_stream_server1.fetch(),
            'server2'   : self.pcap_stream_server2.fetch()
        }
        return buffers

    def sendPacket(self, pkt, node=None):
        if node is None:
            node = self.DEFAULT_NODE
        testNode = getattr(self, 'pcap_stream_{}'.format(node))
        return testNode.sendPkt(pkt)

    def expectPackets(self, node, type='any', pkt=None, timewait_sec=1):
        stream = getattr(self, 'pcap_stream_{}'.format(node))
        if stream is None:
            raise Exception("Invalid node!")
        time.sleep(timewait_sec)
        buffers = stream.fetch()
        matched = []
        idx = 0
        for p in buffers:
            if type == 'any':
                matched.append((p, idx))
            elif type == 'arp':
                if ARP in p:
                    matched.append((p, idx))
            elif type == 'icmp':
                if ICMP in p:
                    matched.append((p, idx))
            elif type == 'ip':
                if IP in p:
                    matched.append((p, idx))
            elif type == 'tcp':
                if TCP in p:
                    matched.append((p, idx))
            elif type == 'udp':
                if UDP in p:
                    matched.append((p, idx))
            else:
                raise Exception("Invalid type!")
            idx += 1
        return matched

    def expectNoPacket(self, sentPkt=None, sentNode=None):
        
        if sentNode is not None and sentNode not in self.NODES:
            raise Exception("Invalid node!")

        buffers = self.fetchPcapBuffers()

        for node in buffers:
            for pkt in buffers[node]:
                if (bytes(pkt) == bytes(sentPkt) and node == sentNode) or IPv6 in pkt:
                    continue
                # print(f"Received at {node}")
                # pkt.show2()
                return False
        return True

    def printPackets(self, pkts):
        idx = 1
        for p in pkts:
            if type(p) is tuple:
                pkt = p[0]
            else:
                pkt = p
            print("{}.\t{}".format(idx, str(pkt)))
            idx += 1

"""
Packet testing utilities.
"""
class PacketTest:
    """
    Observes packets on links instead of ports/interfaces.
    Similar to a tcpdump/wireshark raw capture.
    Caveat: cannot tell direction/source of packets.
    """

    def __init__(self, host_iface, mn_node, debug=False) -> None:
        self.iface = host_iface
        self.node = mn_node
        self.sender_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        'remote_sender.py')
        self.stream = None
        self.buffer = Queue()
        self.debug = debug
        self.stop_flag = False
        if self.debug:
            print("Packet test setup for {} on interface {}.".format(mn_node, host_iface))

    def onPktReceive(self, pkt):
        if self.debug:
            print(f"Received packet on {self.node} interface: {pkt}")
        self.buffer.put(pkt)

    def monitor(self):
        logging.info("Monitoring pcap stream on iface {} ... ".format(self.iface))
        try:
            sniff(iface=self.iface, store=False, prn=self.onPktReceive, stop_filter=lambda _: self.stop_flag)
        except Exception as e:
            print(f"Failed to sniff, {e}")

    def run(self):
        self.stream = threading.Thread(target=self.monitor)
        self.stream.start()
        # time.sleep(1) # Let scapy hook into the interface
    
    def stop(self):
        self.stop_flag = True
        self.sendPkt(Ether(src=0xffffffff, dst=0xffffffff)/ARP())
        self.stream.join(timeout=1)
        if self.stream.is_alive():
            print(f"Failed to stop sniff on {self.node} {self.iface}")

    def fetch(self):
        buffer = []
        while not self.buffer.empty():
            try:
                buffer.append(self.buffer.get(block=False))
            except Empty:
                continue
        return buffer

    def clear(self):
        with self.buffer.mutex:
            unfinished = self.buffer.unfinished_tasks - len(self.buffer.queue)
            if unfinished <= 0:
                if unfinished < 0:
                    raise ValueError('task_done() called too many times')
                self.buffer.all_tasks_done.notify_all()
            self.buffer.unfinished_tasks = unfinished
            self.buffer.queue.clear()
            self.buffer.not_full.notify_all()

    def sendPkt(self, pkt):
        proc = self.node.popen(['python3', self.sender_path, self.node.defaultIntf().name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = proc.communicate(input=pkt.build())
        assert(len(result) > 0)
        result = re.findall("sent ([0-9]+) bytes", str(result[0]))
        assert(len(result) > 0)
        return [pkt]

    # # Does not work, no idea why :) Mostly scapy needs something that is not possible when running sniff in the same process
    # def sendPkt(self, pkt):
    #     iface = self.node.intf().link.intf2
    #     if self.debug:
    #         print(f"Sending to {iface.name}")
    #     sent = sendp(Ether(bytes(pkt)), verbose=False, return_packets=True)
    #     print(f"sent {len(bytes(pkt))} bytes from {self.node} node interface {self.iface}")
    #     return sent
