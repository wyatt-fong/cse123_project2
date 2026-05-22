from base import *
import unittest
import random


class TestRouterEdgeCases(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def _icmp_packets_at_client(self, wait=0.5):
        return [pkt for pkt, _ in self.expectPackets("client", type="icmp", timewait_sec=wait)]

    def test_router_interface_echo_replies(self):
        """The router should answer ICMP echo requests sent to each of its own IPs."""
        for dst_ip in self.gateways:
            self.clearPcapBuffers()
            echo_id = random.randint(1, 65535)
            pkt = (
                Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
                IP(src=self.client["ip"], dst=dst_ip, id=random.randint(1, 65535)) /
                ICMP(type=8, id=echo_id, seq=7) /
                b"router-interface-echo"
            )

            self.sendPacket(pkt, node=self.client["m"].name)

            replies = [
                p for p in self._icmp_packets_at_client()
                if p.haslayer(ICMP)
                and p[ICMP].type == 0
                and p[ICMP].id == echo_id
                and p[IP].src == dst_ip
                and p[IP].dst == self.client["ip"]
            ]
            self.assertTrue(replies, msg=f"Router did not echo-reply from {dst_ip}")

    def test_ttl_expired_generates_time_exceeded(self):
        """A forwarded packet with TTL 1 should produce ICMP type 11/code 0."""
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=self.server1["ip"], ttl=1, id=random.randint(1, 65535)) /
            ICMP(type=8, id=random.randint(1, 65535))
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        errors = [
            p for p in self._icmp_packets_at_client()
            if p.haslayer(ICMP)
            and p[ICMP].type == 11
            and p[ICMP].code == 0
            and p[IP].dst == self.client["ip"]
        ]
        self.assertTrue(errors, msg="Router did not send ICMP time exceeded for TTL 1")

    def test_no_exact_route_generates_net_unreachable(self):
        """A destination missing from rtable should produce ICMP type 3/code 0."""
        self.clearPcapBuffers()
        unrouted_ip = "192.168.2.99"
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=unrouted_ip, id=random.randint(1, 65535)) /
            ICMP(type=8, id=random.randint(1, 65535))
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        errors = [
            p for p in self._icmp_packets_at_client()
            if p.haslayer(ICMP)
            and p[ICMP].type == 3
            and p[ICMP].code == 0
            and p[IP].dst == self.client["ip"]
        ]
        self.assertTrue(errors, msg="Router did not send ICMP net unreachable for missing exact route")

    def test_arp_request_reply_on_incoming_interface_only(self):
        """ARP replies should only be sent for the router IP on the receiving interface."""
        self.clearPcapBuffers()
        good_req = (
            Ether(src=self.client["mac"], dst="ff:ff:ff:ff:ff:ff") /
            ARP(
                op=1,
                hwsrc=self.client["mac"],
                psrc=self.client["ip"],
                hwdst="00:00:00:00:00:00",
                pdst=self.client["gw"],
            )
        )
        self.sendPacket(good_req, node=self.client["m"].name)

        replies = [
            p for p, _ in self.expectPackets("client", type="arp", timewait_sec=0.5)
            if p.haslayer(ARP)
            and p[ARP].op == 2
            and p[ARP].psrc == self.client["gw"]
            and p[ARP].pdst == self.client["ip"]
        ]
        self.assertTrue(replies, msg="Router did not answer ARP for its client-facing IP")

        self.clearPcapBuffers()
        wrong_interface_req = (
            Ether(src=self.client["mac"], dst="ff:ff:ff:ff:ff:ff") /
            ARP(
                op=1,
                hwsrc=self.client["mac"],
                psrc=self.client["ip"],
                hwdst="00:00:00:00:00:00",
                pdst=self.server1["gw"],
            )
        )
        self.sendPacket(wrong_interface_req, node=self.client["m"].name)

        wrong_replies = [
            p for p, _ in self.expectPackets("client", type="arp", timewait_sec=0.5)
            if p.haslayer(ARP)
            and p[ARP].op == 2
            and p[ARP].psrc == self.server1["gw"]
        ]
        self.assertFalse(wrong_replies, msg="Router replied to ARP for an IP on the wrong interface")

    def test_forwarding_sends_arp_on_correct_output_link(self):
        """Forwarding toward server2 should ARP for server2 on the server2 link."""
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
            IP(src=self.client["ip"], dst=self.server2["ip"], id=random.randint(1, 65535)) /
            ICMP(type=8, id=random.randint(1, 65535))
        )

        self.sendPacket(pkt, node=self.client["m"].name)

        arps = [
            p for p, _ in self.expectPackets("server2", type="arp", timewait_sec=0.5)
            if p.haslayer(ARP)
            and p[ARP].op == 1
            and p[ARP].psrc == self.server2["gw"]
            and p[ARP].pdst == self.server2["ip"]
        ]
        self.assertTrue(arps, msg="Router did not ARP for server2 on the server2-facing link")


if __name__ == "__main__":
    unittest.main()
