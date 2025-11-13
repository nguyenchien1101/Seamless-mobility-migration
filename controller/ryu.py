#!/usr/bin/python3

import threading
import time
import heapq
from collections import defaultdict
from dataclasses import dataclass
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet
from ryu.lib.packet import packet, arp, ethernet, ipv4, ether_types
from ryu.ofproto.ofproto_v1_3 import OFPPS_LINK_DOWN, OFPPS_LIVE
from ryu.topology import event
from typing import List

MAX_PATHS = 2

@dataclass
class Paths:
    """ Paths container """
    path: List[int]
    cost: float

class Controller13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapath_list = {}
        self.switches = []
        self.neigh = defaultdict(dict)
        self.hosts = {}
        self.path_table = {}
        self.paths_table = {}
        self.prev_bytes = defaultdict(dict)
        self.bw = defaultdict(dict)
        self.arp_table = {}
        self.path_with_ports_table = {}
        self.active_paths = {}
        self.traffic = {}
        self.no_path_logged = set()
        self.active_paths = {}
        self.traffic = {}
        self.no_path_logged = set()
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match_icmp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_ICMP)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=0,
            priority=1,
            match=match_icmp,
            instructions=inst
        )
        dp.send_msg(mod)
        self.logger.info(f"Installed ICMP flow on switch {dp.id}: send to controller")

        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=0,
            priority=1,
            match=match_arp,
            instructions=inst
        )
        dp.send_msg(mod)
        self.logger.info(f"Installed ARP flow on switch {dp.id}: send to controller")

        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=0,
            priority=0,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)
        self.logger.info(f"Table-miss for table 0 on switch {dp.id}: goto table 1")

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=1,
            priority=0,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)

    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        """
        Tính path đồng bộ rồi cài flow cho ICMP & ARP giữa ip_src và ip_dst.
        """
        self.active_paths.setdefault((ip_src, ip_dst), {})


        ports_map = self.compute_paths(src, first_port, dst, last_port)
        if not ports_map:
            self.logger.warning(
                f"No computed path for ({src},{first_port},{dst},{last_port}), "
                f"fallback to FLOOD for {ip_src}->{ip_dst}"
            )
            return None


        for node, (in_port, out_port) in ports_map.items():
            dp = self.datapath_list.get(node)
            if not dp:
                self.logger.warning(f"Datapath for switch {node} not found, skip")
                continue

            parser = dp.ofproto_parser
            actions = [parser.OFPActionOutput(out_port)]

            # Flow cho ICMP
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_src,
                ipv4_dst=ip_dst,
                ip_proto=inet.IPPROTO_ICMP
            )
            self.add_flow(dp, 22222, match, actions, idle_timeout=30)
            self.logger.info(
                f"ICMP flow installed on switch {node}, in_port={in_port}, out_port={out_port}"
            )

            # Flow cho ARP
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_ARP,
                arp_spa=ip_src,
                arp_tpa=ip_dst
            )
            self.add_flow(dp, 11111, match, actions, idle_timeout=30)
            self.logger.info(
                f"ARP flow installed on switch {node}, in_port={in_port}, out_port={out_port}"
            )


        self.active_paths[(ip_src, ip_dst)] = ports_map


        return ports_map.get(src, (None, None))[1]


    def compute_paths(self, src, first_port, dst, last_port):
        """
        Tính đường đi & gắn port theo kiểu đồng bộ.
        Trả về dict {dpid: (in_port, out_port)} cho path tối ưu,
        hoặc None nếu không có path.
        """
        key_pair = (src, dst)

        paths = self.find_paths_and_costs(src, dst)
        if not paths:
            if key_pair not in self.no_path_logged:
                self.logger.info(
                    f"No paths found between {src} and {dst} "
                    f"(further messages for this pair will be suppressed)"
                )
                self.no_path_logged.add(key_pair)
            return None


        path_list = self.find_n_optimal_paths(paths)
        if not path_list:
            if key_pair not in self.no_path_logged:
                self.logger.info(
                    f"No optimal paths selected between {src} and {dst} "
                    f"(further messages for this pair will be suppressed)"
                )
                self.no_path_logged.add(key_pair)
            return None


        if key_pair in self.no_path_logged:
            self.no_path_logged.remove(key_pair)


        path_with_port_list = self.add_ports_to_paths(path_list, first_port, last_port)
        path_with_port = path_with_port_list[0]

        self.logger.info(f"Optimal Path with port: {path_with_port}")


        key = (src, first_port, dst, last_port)
        self.paths_table[key] = paths
        self.path_table[key] = path_list
        self.path_with_ports_table[key] = path_with_port_list

        return path_with_port


    def find_paths_and_costs(self, src, dst):
        """
        Implementation of Breath-First Search Algorithm (BFS)
        Output of this function returns a list on class Paths objects
        """
        if src == dst:
            return [Paths([src], 0)]
        queue = [(src, [src])]
        possible_paths = list()
        while queue:
            (edge, path) = queue.pop()
            for vertex in set(self.neigh[edge]) - set(path):
                if vertex == dst:
                    path_to_dst = path + [vertex]
                    cost_of_path = self.find_path_cost(path_to_dst)
                    possible_paths.append(Paths(path_to_dst, cost_of_path))
                else:
                    queue.append((vertex, path + [vertex]))
        return possible_paths

    def find_n_optimal_paths(self, paths, number_of_optimal_paths=MAX_PATHS):
        """arg paths is a list containing lists of possible paths"""
        if not paths:
            return []

        number_of_optimal_paths = min(number_of_optimal_paths, len(paths))

        costs = [path.cost for path in paths]
        optimal_paths_indexes = list(
            map(costs.index, heapq.nsmallest(number_of_optimal_paths, costs))
        )
        optimal_paths = [paths[op_index] for op_index in optimal_paths_indexes]
        return optimal_paths


    def add_ports_to_paths(self, paths, first_port, last_port):
        """
        Add the ports to all switches including hosts
        """
        paths_n_ports = list()
        bar = dict()
        in_port = first_port
        for s1, s2 in zip(paths[0].path[:-1], paths[0].path[1:]):
            out_port = self.neigh[s1][s2]
            bar[s1] = (in_port, out_port)
            in_port = self.neigh[s2][s1]
        bar[paths[0].path[-1]] = (in_port, last_port)
        paths_n_ports.append(bar)
        return paths_n_ports

    def add_flow(self, datapath, priority, match, actions, idle_timeout, buffer_id=None):
        """ Method Provided by the source Ryu library."""

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=idle_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_timeout, instructions=inst)
        datapath.send_msg(mod)

    def find_path_cost(self, path):
        """
        arg path is a list with all nodes in our route

        Cost = alpha * hop_count + beta * total_link_load

        - hop_count: số link (số switch-đến-switch) trên đường đi
        - total_link_load: tổng băng thông đang sử dụng trên các link trong path (Mbps)
        - alpha, beta: hệ số trọng số
        """
        hop_count = len(path) - 1
        if hop_count <= 0:
            return 0

        total_load = 0.0
        i = 0
        while i < len(path) - 1:
            port1 = self.neigh[path[i]][path[i + 1]]
            link_load = self.get_bandwidth(path, port1, i)
            total_load += link_load
            i += 1

        alpha = 1.0   
        beta = 0.1    

        return alpha * hop_count + beta * total_load


    def get_bandwidth(self, path, port, index):
        dpid = path[index]
        
        return self.bw.get(dpid, {}).get(port, 0.0)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        stats = ev.msg.body
        dp = ev.msg.datapath
        dpid = dp.id
        self.bw.setdefault(dpid, {})
        self.prev_bytes.setdefault(dpid, {})
        for p in stats:
            port_no = p.port_no
            if port_no == dp.ofproto.OFPP_LOCAL:
                continue
            prev = self.prev_bytes[dpid].get(port_no, p.tx_bytes)
            bw_val = (p.tx_bytes - prev) * 8.0 / 1e6
            self.bw[dpid][port_no] = bw_val
            self.prev_bytes[dpid][port_no] = p.tx_bytes
        self.logger.debug(f"BW stats for switch {dpid}: {self.bw[dpid]}")

    def run_check(self, ofp_parser, dp):
        threading.Timer(1.0, self.run_check, args=(ofp_parser, dp)).start()
        req = ofp_parser.OFPPortStatsRequest(dp)
        dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        if src_mac not in self.hosts:
            self.hosts[src_mac] = (dpid, in_port)

        out_port = ofp.OFPP_FLOOD

       # self.start_discovery()

        if eth.ethertype == ether_types.ETH_TYPE_ARP and arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            self.traffic.setdefault(src_ip, set())
            self.traffic[src_ip].add(dst_ip)

            self.logger.info(
                f"Received ARP packet: opcode={arp_pkt.opcode}, src_ip={src_ip}, dst_ip={dst_ip}, src_mac={src_mac}, dst_mac={dst_mac} on switch {dpid}")

            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src_mac
                h1 = self.hosts[src_mac]
                h2 = self.hosts[dst_mac]

                self.logger.info(f" ARP Reply from: {src_ip} to: {dst_ip} H1: {h1} H2: {h2}")

                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip)

                if out_port is None:
                    out_port = ofp.OFPP_FLOOD


            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src_mac
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src_mac]
                    if dst_mac in self.hosts:
                        h2 = self.hosts[dst_mac]
                        self.logger.info(f" ARP Reply from: {src_ip} to: {dst_ip} H1: {h1} H2: {h2}")
                        out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                        self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip)

                        if out_port is None:
                            out_port = ofp.OFPP_FLOOD


        if eth.ethertype == ether_types.ETH_TYPE_IP and ip_pkt and ip_pkt.proto == inet.IPPROTO_ICMP:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            self.arp_table[src_ip] = src_mac

            self.logger.debug(f"IP Proto ICMP from: {src_ip} to: {dst_ip}")

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

    def remove_flows(self, path):
        for dpid, (in_port, out_port) in path.items():
            datapath = self.datapath_list.get(dpid)
            if not datapath:
                self.logger.warning(f"remove_flows: datapath {dpid} not found, skip")
                continue
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(in_port=in_port)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=out_port,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            datapath.send_msg(mod)


    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch_dp = ev.switch.dp
        switch_dpid = switch_dp.id
        ofp_parser = switch_dp.ofproto_parser

        self.logger.info(f"Switch has been plugged in PID: {switch_dpid}")

        if switch_dpid not in self.switches:
            self.datapath_list[switch_dpid] = switch_dp
            self.switches.append(switch_dpid)
            self.run_check(ofp_parser, switch_dp)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        switch = ev.switch.dp.id
        if switch in self.switches:
            try:
                self.switches.remove(switch)
                del self.datapath_list[switch]
                del self.neigh[switch]
            except KeyError:
                self.logger.info(f"Switch has been already plugged off PID{switch}!")

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        self.neigh[ev.link.src.dpid][ev.link.dst.dpid] = ev.link.src.port_no
        self.neigh[ev.link.dst.dpid][ev.link.src.dpid] = ev.link.dst.port_no
        self.logger.info(
            f"Link between switches has been established, SW1 DPID: {ev.link.src.dpid}:{ev.link.dst.port_no} SW2 DPID: {ev.link.dst.dpid}:{ev.link.dst.port_no}")

    def find_affected_paths(self, deleted_link):
        res = []
        s = deleted_link.src.dpid
        d = deleted_link.dst.dpid
        for (src, dst), paths in self.active_paths.items():
            dpids = list(paths.keys())
            for i in range(len(dpids) - 1):
                if (dpids[i] == s and dpids[i + 1] == d) or (dpids[i] ==d and dpids[i + 1] == s):
                    res.append((src, dst, paths))
                    break
        return res

    def find_affected_paths_by_port(self, dpid, port):
        res = []
        for (src, dst), paths in self.active_paths.items():
            if dpid not in paths:
                continue
            in_port, out_port = paths[dpid]
            if in_port == port or out_port == port:
                res.append((src, dst, paths))
        return res

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        try:
            src_dpid = ev.link.src.dpid
            dst_dpid = ev.link.dst.dpid

            del self.neigh[src_dpid][dst_dpid]
            del self.neigh[dst_dpid][src_dpid]

            affected_paths = self.find_affected_paths(ev.link)

            for src, dst, path in affected_paths:
                self.logger.info("Removing flows between %s and %s", src, dst)
                self.remove_flows(path)
                del self.active_paths[(src, dst)]

        except KeyError:
            self.logger.info("Link has been already plugged off!")

    @set_ev_cls(event.EventHostAdd)
    def _host_add_handler(self, ev):
        host = ev.host
        dpid = host.port.dpid
        port = host.port.port_no
        self.logger.info(f"New host detected: MAC {host.mac}, IPs {host.ipv4} on switch {dpid} - port {port}")
        self.hosts[host.mac] = (dpid, port)
        self.arp_table[host.ipv4[0]] = host.mac

    def remove_paths_by_port(self, datapath, port):
        affected_paths = self.find_affected_paths_by_port(datapath.id, port.port_no)

        for src, dst, path in affected_paths:
            self.logger.info("Removing flows between %s and %s", src, dst)
            self.remove_flows(path)
            del self.active_paths[(src, dst)]

    def send_repre_arp_request(self, moved_host_ip, datapath):
        time.sleep(0.5)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Dùng .get để tránh KeyError
        for src_ip in self.traffic.get(moved_host_ip, set()):
            src_mac = self.arp_table.get(src_ip)
            if not src_mac:
                self.logger.warning(
                    f"send_repre_arp_request: no MAC found for src_ip {src_ip}"
                )
                continue

            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                src=src_mac,
                dst='ff:ff:ff:ff:ff:ff'))
            pkt.add_protocol(arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=src_mac,
                src_ip=src_ip,
                dst_mac='00:00:00:00:00:00',
                dst_ip=moved_host_ip))

            pkt.serialize()
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=pkt.data)
            datapath.send_msg(out)
            self.logger.info(f"ARP REQUEST from {src_ip}:{src_mac} to {moved_host_ip}")


    def get_ip_by_mac(self, mac):
        for ip, mac_addr in self.arp_table.items():
            if mac == mac_addr:
                return ip

    def get_mac_down_port(self, dpid, port):
        for key, data in self.hosts.items():
            if data[0] == dpid and data[1] == port:
                return key

    def handle_down_port(self, dpid, port):
        moved_host_mac = self.get_mac_down_port(dpid, port.port_no)
        if not moved_host_mac:
            return

        moved_host_ip = self.get_ip_by_mac(moved_host_mac)
        if not moved_host_ip:
            self.logger.warning(
                f"handle_down_port: no IP found for MAC {moved_host_mac}"
            )
            return

        datapath = self.datapath_list.get(dpid)
        if not datapath:
            self.logger.warning(
                f"handle_down_port: datapath {dpid} not found, skip ARP rediscovery"
            )
            return

        # Xóa host khỏi bảng
        self.hosts.pop(moved_host_mac, None)

        threading.Thread(
            target=self.send_repre_arp_request,
            args=(moved_host_ip, datapath)
        ).start()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        port = ev.msg.desc
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        if port.port_no == ofproto.OFPP_LOCAL:
            return

        if ev.msg.reason == ofproto.OFPPR_ADD:
            self.logger.info(f"Port {port.port_no} is added to switch {datapath.id}")

        elif ev.msg.reason == ofproto.OFPPR_DELETE:
            self.logger.info(f"Port {port.port_no} is removed from switch {datapath.id}")
            self.remove_paths_by_port(datapath, port)
            self.handle_down_port(dpid, port)

        elif ev.msg.reason == ofproto.OFPPR_MODIFY:
            if port.state & OFPPS_LINK_DOWN:
                self.logger.info(f"Port {port.port_no} of switch {datapath.id} is DOWN")
                self.remove_paths_by_port(datapath, port)
                self.handle_down_port(dpid, port)

            elif port.state & OFPPS_LIVE:
                self.logger.info(f"Port {port.port_no} of switch {datapath.id} is UP")
# End of Controller13
