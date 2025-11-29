from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import time
import logging

LOG = logging.getLogger('ryu.app.dynamic_firewall')

class DynamicFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    DEFAULT_PKT_THRESHOLD = 100

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.ip_pkt_counts = {}
        self.pkt_threshold = int(kwargs.get('pkt_threshold', self.DEFAULT_PKT_THRESHOLD))
        self.poll_interval = 5  
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        LOG.info("Installed table-miss on %s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange)
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == 0 and datapath.id in self.datapaths:
            del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == 0x0800: 
            ip = pkt.get_protocol(ipv4.ipv4)
            src = ip.src
            self.ip_pkt_counts[src] = self.ip_pkt_counts.get(src, 0) + 1

        return

    def _monitor(self):
        while True:
            for dp_id, datapath in list(self.datapaths.items()):
                self._request_flow_stats(datapath)
                self._request_port_stats(datapath)
            self._evaluate_counters()
            hub.sleep(self.poll_interval)

    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _request_port_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        pass

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply(self, ev):
        pass

    def _evaluate_counters(self):
        to_block = []
        for ip, count in list(self.ip_pkt_counts.items()):
            if count >= self.pkt_threshold:
                to_block.append(ip)
                LOG.info("IP %s exceeded threshold (%d >= %d)", ip, count, self.pkt_threshold)
                del self.ip_pkt_counts[ip]

        for ip in to_block:
            for dp in list(self.datapaths.values()):
                self._install_block_flow(dp, ip)

    def _install_block_flow(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        inst = []
        mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst, hard_timeout=60)
        datapath.send_msg(mod)
        LOG.info("Installed DROP flow for %s on datapath %s", src_ip, datapath.id)