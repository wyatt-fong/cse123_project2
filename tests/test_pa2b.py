from base import *
import unittest
import random
import re


class TestPA2BFunctionality(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False,
                              manual_sr=False, pa2b=True)

    def tearDown(self):
        self.tearDownEnvironment()

    def _client_icmp_packets(self, wait=0.7):
        return [pkt for pkt, _ in self.expectPackets("client", type="icmp", timewait_sec=wait)]

    def _assert_ping_received(self, host, dst, name):
        output = host["m"].cmd("ping -c 3 -W 3 {}".format(dst["ip"]))
        received = re.search(r"(\d+) (packets )?received", output)
        self.assertTrue(received and int(received.group(1)) > 0,
                        msg="ICMP request failed between {} and {}:\n{}".format(
                            host["m"].name, name, output))

    def _assert_traceroute_reached(self, host, dst, name):
        output = host["m"].cmd("traceroute -w 2 -q 3 {}".format(dst["ip"]))
        hop_lines = [
            line for line in output.splitlines()
            if re.match(r"^\s*\d+\s+", line)
        ]
        reached = any(dst["ip"] in line for line in hop_lines)
        self.assertTrue(reached,
                        msg="Traceroute did not reach {}:\n{}".format(name, output))

    def _assert_http_reached(self, host, dst, name):
        output = host["m"].cmd("wget -T 5 -t 1 -O- http://{}".format(dst["ip"]))
        self.assertIn("Congratulations", output,
                      msg="HTTP request did not reach {}:\n{}".format(name, output))

    def test_ping_servers_through_multi_router_topology(self):
        self._assert_ping_received(self.client, self.server1, "server1")
        self._assert_ping_received(self.client, self.server2, "server2")

    def test_icmp_echo_request_is_forwarded_to_servers(self):
        for dst_name, dst in [("server1", self.server1), ("server2", self.server2)]:
            self.clearPcapBuffers()
            echo_id = random.randint(1, 65535)
            pkt = (
                Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
                IP(src=self.client["ip"], dst=dst["ip"], id=random.randint(1, 65535)) /
                ICMP(type=8, id=echo_id, seq=1)
            )

            self.sendPacket(pkt, node=self.client["m"].name)

            requests = [
                p for p, _ in self.expectPackets(dst["m"].name, type="icmp", timewait_sec=3)
                if p.haslayer(ICMP)
                and p[ICMP].type == 8
                and p[ICMP].id == echo_id
                and p[IP].src == self.client["ip"]
                and p[IP].dst == dst["ip"]
            ]
            self.assertTrue(requests,
                            msg="Router path did not forward ICMP echo request to {}".format(dst_name))

    def test_traceroute_reaches_servers(self):
        self._assert_traceroute_reached(self.client, self.server1, "server1")
        self._assert_traceroute_reached(self.client, self.server2, "server2")

    def test_tcp_http_reaches_servers(self):
        self._assert_http_reached(self.client, self.server1, "server1")
        self._assert_http_reached(self.client, self.server2, "server2")

    def test_udp_to_router_generates_port_unreachable(self):
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=self.client["gw"], id=random.randint(1, 65535)) /
            UDP(sport=33434, dport=33434) /
            b"traceroute-probe"
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        errors = [
            p for p in self._client_icmp_packets()
            if p.haslayer(ICMP)
            and p[ICMP].type == 3
            and p[ICMP].code == 3
            and p[IP].src == self.client["gw"]
            and p[IP].dst == self.client["ip"]
        ]
        self.assertTrue(errors, msg="Router did not send ICMP port unreachable for UDP to itself")

    def test_tcp_to_router_generates_port_unreachable(self):
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=self.client["gw"], id=random.randint(1, 65535)) /
            TCP(sport=49152, dport=80, flags="S")
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        errors = [
            p for p in self._client_icmp_packets()
            if p.haslayer(ICMP)
            and p[ICMP].type == 3
            and p[ICMP].code == 3
            and p[IP].src == self.client["gw"]
            and p[IP].dst == self.client["ip"]
        ]
        self.assertTrue(errors, msg="Router did not send ICMP port unreachable for TCP to itself")


if __name__ == "__main__":
    unittest.main()
