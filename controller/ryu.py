#!/usr/bin/python3

import heapq
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import List

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet
from ryu.lib.packet import packet, arp, ethernet, ipv4, ether_types
from ryu.ofproto.ofproto_v1_3 import OFPPS_LINK_DOWN, OFPPS_LIVE
from ryu.topology import event
from ryu.lib import hub

MAX_PATHS = 2

@dataclass
class Paths:
    path: List[int]
    cost: float


class Controller13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    COOKIE = 0x13  # cookie riêng cho app này

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Topology & datapaths
        self.datapath_list = {}                 
        self.switches = []                      
        self.neigh = defaultdict(dict)          

        # Hosts & ARP
        self.hosts = {}                         
        self.arp_table = {}                     

        # Paths
        self.path_table = {}                    
        self.path_with_ports_table = {}         
        self.active_paths = {}                  

        # Traffic & stats
        self.traffic = defaultdict(set)         
        self.prev_bytes = defaultdict(dict)     
        self.bw = defaultdict(dict)             

        # Periodic port stats
        self.port_stats_thread = hub.spawn(self._port_stats_loop)

    # ========= Switch features / pipeline =========

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # ICMP -> controller (debug / học topo)
        match_icmp = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=inet.IPPROTO_ICMP
        )
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=0,
            priority=10,
            match=match_icmp,
            instructions=inst,
            cookie=self.COOKIE
        )
        dp.send_msg(mod)

        # ARP -> controller
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=0,
            priority=10,
            match=match_arp,
            instructions=inst,
            cookie=self.COOKIE
        )
        dp.send_msg(mod)

        # Table-miss -> goto table 1
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=0,
            priority=0,
            match=match,
            instructions=inst,
            cookie=self.COOKIE
        )
        dp.send_msg(mod)

        # Table 1 default: flood (chỉ khi chưa có rule tốt hơn)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=1,
            priority=0,
            match=match,
            instructions=inst,
            cookie=self.COOKIE
        )
        dp.send_msg(mod)

        self.logger.info("Configured base pipeline on switch %s", dp.id)

    # ========= Port stats (bandwidth) =========

    def _port_stats_loop(self):
        while True:
            try:
                for dp in list(self.datapath_list.values()):
                    ofp = dp.ofproto
                    parser = dp.ofproto_parser
                    req = parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY)
                    dp.send_msg(req)
            except Exception as e:
                self.logger.error("Port stats loop error: %s", e)
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        self.bw.setdefault(dpid, {})
        self.prev_bytes.setdefault(dpid, {})

        for p in ev.msg.body:
            port_no = p.port_no
            if port_no == dp.ofproto.OFPP_LOCAL:
                continue

            prev = self.prev_bytes[dpid].get(port_no, p.tx_bytes)
            delta = p.tx_bytes - prev
            bw_val = max(delta, 0) * 8.0 / 1e6  # Mbps (tx only)
            self.bw[dpid][port_no] = bw_val
            self.prev_bytes[dpid][port_no] = p.tx_bytes

        self.logger.debug("BW stats for switch %s: %s", dpid, self.bw[dpid])

    # ========= Flow utils =========

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, buffer_id=None):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            idle_timeout=idle_timeout,
            instructions=inst,
            cookie=self.COOKIE
        )
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    def remove_flows(self, path_ports):
        # Xóa các flow theo in_port + cookie của app
        for dpid, (in_port, _out_port) in path_ports.items():
            dp = self.datapath_list.get(dpid)
            if not dp:
                continue
            ofp = dp.ofproto
            parser = dp.ofproto_parser

            match = parser.OFPMatch(in_port=in_port)
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=match,
                cookie=self.COOKIE,
                cookie_mask=0xffffffffffffffff
            )
            dp.send_msg(mod)

    # ========= Path computation (BFS) =========

    def find_paths_and_costs(self, src, dst):
        if src == dst:
            return [Paths([src], 0)]

        queue = deque([(src, [src])])
        possible_paths = []

        while queue:
            node, path = queue.popleft()
            for nxt in set(self.neigh[node].keys()) - set(path):
                new_path = path + [nxt]
                if nxt == dst:
                    cost = self.find_path_cost(new_path)
                    possible_paths.append(Paths(new_path, cost))
                else:
                    queue.append((nxt, new_path))

        return possible_paths

    def find_path_cost(self, path):
        # Hiện tại: cost = số hop (dễ hiểu, ổn định)
        # Có thể nâng cấp: kết hợp hop + băng thông + delay
        return len(path) - 1

    def find_n_optimal_paths(self, paths, number_of_optimal_paths=MAX_PATHS):
        if not paths:
            return []
        number_of_optimal_paths = min(number_of_optimal_paths, len(paths))
        costs = [p.cost for p in paths]
        idxs = list(map(costs.index, heapq.nsmallest(number_of_optimal_paths, costs)))
        return [paths[i] for i in idxs]

    def add_ports_to_path(self, path_obj, first_port, last_port):
        # Gắn in/out port cho từng switch trên path
        path = path_obj.path
        ports = {}
        in_port = first_port

        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = self.neigh[s1][s2]
            ports[s1] = (in_port, out_port)
            in_port = self.neigh[s2][s1]

        ports[path[-1]] = (in_port, last_port)
        return ports

    # ========= Compute + install path =========

    def compute_and_install_path(self, src_sw, src_port, dst_sw, dst_port,
                                 ip_src, ip_dst):
        paths = self.find_paths_and_costs(src_sw, dst_sw)
        if not paths:
            self.logger.warning("No path between switches %s and %s", src_sw, dst_sw)
            return None

        best = self.find_n_optimal_paths(paths, 1)[0]
        path_ports = self.add_ports_to_path(best, src_port, dst_port)

        for dpid, (in_port, out_port) in path_ports.items():
            dp = self.datapath_list.get(dpid)
            if not dp:
                continue
            parser = dp.ofproto_parser

            # IP traffic ip_src -> ip_dst
            match_ip = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_src,
                ipv4_dst=ip_dst
            )
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(dp, priority=100, match=match_ip,
                          actions=actions, idle_timeout=60)

            # ARP giữa 2 host này
            match_arp = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_ARP,
                arp_spa=ip_src,
                arp_tpa=ip_dst
            )
            self.add_flow(dp, priority=90, match=match_arp,
                          actions=actions, idle_timeout=60)

            self.logger.info(
                "Installed path on switch %s: %s -> %s via in_port=%s out_port=%s",
                dpid, ip_src, ip_dst, in_port, out_port
            )

        # Lưu lại
        self.path_table[(ip_src, ip_dst)] = best.path
        self.path_with_ports_table[(ip_src, ip_dst)] = path_ports
        self.active_paths[(ip_src, ip_dst)] = path_ports

        first_hop = best.path[0]
        return path_ports.get(first_hop, (None, None))[1]

    def _try_install_for_hosts(self, src_ip, dst_ip, src_mac, dst_mac):
        if src_mac not in self.hosts or dst_mac not in self.hosts:
            return None

        src_sw, src_port = self.hosts[src_mac]
        dst_sw, dst_port = self.hosts[dst_mac]

        out_port = self.compute_and_install_path(
            src_sw, src_port, dst_sw, dst_port, src_ip, dst_ip
        )
        # cài luôn path ngược
        self.compute_and_install_path(
            dst_sw, dst_port, src_sw, src_port, dst_ip, src_ip
        )

        return out_port

    # ========= PacketIn =========

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # Học host
        if src_mac not in self.hosts:
            self.hosts[src_mac] = (dpid, in_port)
            self.logger.info("Learned host %s at %s:%s", src_mac, dpid, in_port)

        out_port = ofp.OFPP_FLOOD

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # ARP
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            self.arp_table[src_ip] = src_mac
            self.traffic[src_ip].add(dst_ip)

            self.logger.info(
                "ARP opcode=%s %s(%s) -> %s(%s) on %s",
                arp_pkt.opcode, src_ip, src_mac, dst_ip, dst_mac, dpid
            )

            if arp_pkt.opcode == arp.ARP_REPLY:
                if dst_mac in self.hosts:
                    port = self._try_install_for_hosts(src_ip, dst_ip, src_mac, dst_mac)
                    if port is not None:
                        out_port = port

            elif arp_pkt.opcode == arp.ARP_REQUEST:
                dst_mac_known = self.arp_table.get(dst_ip)
                if dst_mac_known and dst_mac_known in self.hosts:
                    port = self._try_install_for_hosts(src_ip, dst_ip, src_mac, dst_mac_known)
                    if port is not None:
                        out_port = port

        # IP (ICMP/TCP/UDP, match full ip_src/ip_dst)
        elif ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            self.arp_table[src_ip] = src_mac

            self.logger.info(
                "IP proto=%s %s(%s) -> %s(%s)",
                ip_pkt.proto, src_ip, src_mac, dst_ip, dst_mac, dpid
            )

            if dst_mac in self.hosts:
                port = self._try_install_for_hosts(src_ip, dst_ip, src_mac, dst_mac)
                if port is not None:
                    out_port = port

        # Gửi tiếp
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        )
        dp.send_msg(out)

    # ========= Topology events =========

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dp = ev.switch.dp
        dpid = dp.id
        if dpid not in self.switches:
            self.switches.append(dpid)
            self.datapath_list[dpid] = dp
        self.logger.info("Switch %s connected", dpid)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        dpid = ev.switch.dp.id
        if dpid in self.switches:
            self.switches.remove(dpid)
            self.datapath_list.pop(dpid, None)
            self.neigh.pop(dpid, None)
            self.logger.info("Switch %s disconnected", dpid)

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst

        self.neigh[src.dpid][dst.dpid] = src.port_no
        self.neigh[dst.dpid][src.dpid] = dst.port_no

        self.logger.info(
            "Link up: %s:%s <-> %s:%s",
            src.dpid, src.port_no, dst.dpid, dst.port_no
        )

    # ========= Affected paths detection =========

    def find_affected_paths(self, s, d):
        affected = []
        for (ip_src, ip_dst), path in self.path_table.items():
            for i in range(len(path) - 1):
                if (path[i] == s and path[i+1] == d) or (path[i] == d and path[i+1] == s):
                    affected.append((ip_src, ip_dst))
                    break
        return affected

    def find_affected_paths_by_port(self, dpid, port_no):
        affected = []
        for (ip_src, ip_dst), path_ports in self.active_paths.items():
            if dpid not in path_ports:
                continue
            in_port, out_port = path_ports[dpid]
            if in_port == port_no or out_port == port_no:
                affected.append((ip_src, ip_dst))
        return affected

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s = ev.link.src.dpid
        d = ev.link.dst.dpid

        self.neigh[s].pop(d, None)
        self.neigh[d].pop(s, None)

        self.logger.info("Link down: %s <-> %s", s, d)

        for ip_src, ip_dst in self.find_affected_paths(s, d):
            path_ports = self.active_paths.get((ip_src, ip_dst))
            if path_ports:
                self.logger.info(
                    "Removing flows for %s -> %s due to link down",
                    ip_src, ip_dst
                )
                self.remove_flows(path_ports)
                self.active_paths.pop((ip_src, ip_dst), None)

            src_mac = self.arp_table.get(ip_src)
            dst_mac = self.arp_table.get(ip_dst)
            if src_mac in self.hosts and dst_mac in self.hosts:
                src_sw, src_port = self.hosts[src_mac]
                dst_sw, dst_port = self.hosts[dst_mac]
                self.compute_and_install_path(
                    src_sw, src_port, dst_sw, dst_port, ip_src, ip_dst
                )

    # ========= Host & Port status (mobility / failure) =========

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        host = ev.host
        dpid = host.port.dpid
        port = host.port.port_no
        mac = host.mac
        ips = host.ipv4

        self.hosts[mac] = (dpid, port)
        if ips:
            self.arp_table[ips[0]] = mac

        self.logger.info(
            "Host added: %s ips=%s at %s:%s",
            mac, ips, dpid, port
        )

    def get_ip_by_mac(self, mac):
        for ip, m in self.arp_table.items():
            if m == mac:
                return ip
        return None

    def get_mac_down_port(self, dpid, port_no):
        for mac, (sw, p) in list(self.hosts.items()):
            if sw == dpid and p == port_no:
                return mac
        return None

    def send_rearp_requests(self, moved_ip, datapath):
        hub.sleep(0.5)
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        for src_ip in list(self.traffic.get(moved_ip, [])):
            src_mac = self.arp_table.get(src_ip)
            if not src_mac:
                continue

            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                src=src_mac,
                dst='ff:ff:ff:ff:ff:ff'
            ))
            pkt.add_protocol(arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=src_mac,
                src_ip=src_ip,
                dst_mac='00:00:00:00:00:00',
                dst_ip=moved_ip
            ))
            pkt.serialize()

            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=ofp.OFPP_CONTROLLER,
                actions=actions,
                data=pkt.data
            )
            datapath.send_msg(out)

            self.logger.info(
                "Re-ARP sent from %s(%s) to %s",
                src_ip, src_mac, moved_ip
            )

    def handle_down_port(self, dpid, port_no):
        moved_mac = self.get_mac_down_port(dpid, port_no)
        if not moved_mac:
            return

        moved_ip = self.get_ip_by_mac(moved_mac)
        if not moved_ip:
            return

        self.hosts.pop(moved_mac, None)
        dp = self.datapath_list.get(dpid)
        if dp:
            hub.spawn(self.send_rearp_requests, moved_ip, dp)

    def remove_paths_by_port(self, dpid, port_no):
        for ip_src, ip_dst in self.find_affected_paths_by_port(dpid, port_no):
            path_ports = self.active_paths.get((ip_src, ip_dst))
            if path_ports:
                self.logger.info(
                    "Removing flows for %s -> %s due to port %s on switch %s",
                    ip_src, ip_dst, port_no, dpid
                )
                self.remove_flows(path_ports)
                self.active_paths.pop((ip_src, ip_dst), None)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofp = dp.ofproto
        port = msg.desc

        if port.port_no == ofp.OFPP_LOCAL:
            return

        if msg.reason == ofp.OFPPR_ADD:
            self.logger.info("Port %s added on switch %s", port.port_no, dpid)

        elif msg.reason == ofp.OFPPR_DELETE:
            self.logger.info("Port %s deleted on switch %s", port.port_no, dpid)
            self.remove_paths_by_port(dpid, port.port_no)
            self.handle_down_port(dpid, port.port_no)

        elif msg.reason == ofp.OFPPR_MODIFY:
            if port.state & OFPPS_LINK_DOWN:
                self.logger.info("Port %s on switch %s is DOWN", port.port_no, dpid)
                self.remove_paths_by_port(dpid, port.port_no)
                self.handle_down_port(dpid, port.port_no)
            elif port.state & OFPPS_LIVE:
                self.logger.info("Port %s on switch %s is UP/LIVE", port.port_no, dpid)

