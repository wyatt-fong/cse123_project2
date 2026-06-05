from base import *
import unittest
import random


class TestPA2BFunctionality(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False,
                              manual_sr=False, pa2b=True)

    def tearDown(self):
        self.tearDownEnvironment()

    def _client_icmp_packets(self, wait=0.7):
        return [pkt for pkt, _ in self.expectPackets("client", type="icmp", timewait_sec=wait)]

    def test_ping_servers_through_multi_router_topology(self):
        output = self.client["m"].cmd("ping -c 1 {}".format(self.server1["ip"]))
        self.assertTrue("1 packets received" in output,
                        msg="ICMP request failed between client and server1")

        output = self.client["m"].cmd("ping -c 1 {}".format(self.server2["ip"]))
        self.assertTrue("1 packets received" in output,
                        msg="ICMP request failed between client and server2")

    def test_traceroute_reaches_servers(self):
        output = self.client["m"].cmd("traceroute {}".format(self.server1["ip"]))
        self.assertIn(self.server1["ip"], output,
                      msg="Traceroute did not reach server1")

        output = self.client["m"].cmd("traceroute {}".format(self.server2["ip"]))
        self.assertIn(self.server2["ip"], output,
                      msg="Traceroute did not reach server2")

    def test_tcp_http_reaches_servers(self):
        output = self.client["m"].cmd("wget -T 5 -O- http://{}".format(self.server1["ip"]))
        self.assertIn("Congratulations", output,
                      msg="HTTP request did not reach server1")

        output = self.client["m"].cmd("wget -T 5 -O- http://{}".format(self.server2["ip"]))
        self.assertIn("Congratulations", output,
                      msg="HTTP request did not reach server2")

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
