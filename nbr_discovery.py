from ryu.base import app_manager
from ryu.controller import ofp_event

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import inet
from ryu.lib.packet import ipv4
import requests
from requests.auth import HTTPDigestAuth
import json
from pprint import pprint

from ryu.lib.packet import arp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.ofproto import ether


"""db0: nbr discovery
    RLOC, DPID, NBR MAC, o/p port NBR"""


# variables declared here

db0={"3.0.0.1":{},'5.0.0.1':{}}
dpidToIp={'161442412056386':'3.0.0.1','223103364804175':'5.0.0.1'}
ipToNbr={'3.0.0.1':'3.0.0.2','5.0.0.1':'5.0.0.2'}



class ExampleSwitch13(app_manager.RyuApp):
    


    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    
    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.nbr_discovery(ev)


    def nbr_discovery(self, ev ):
        self.logger.info("nbr discovery process starts")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        xtr_ip=dpidToIp[str(datapath.id)]
        nbr_ip=ipToNbr[xtr_ip]
        self.logger.info(datapath.id)
        self.send_arp(datapath, 1, "00:0a:00:0a:00:00", xtr_ip, "ff:ff:ff:ff:ff:ff", nbr_ip, ofproto.OFPP_FLOOD)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        inPort = msg.match['in_port']

        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)
        self.logger.info("packet in recv ")
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            self.receive_arp(dp, packet, etherFrame, inPort)
            return 0
        else:
            self.logger.info("Drop packet")
            return 1


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)


    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp)

        if arpPacket.opcode == 1:
            arp_dstIp = arpPacket.dst_ip
            self.logger.info("receive ARP request %s => %s (port%d)"
                       %(etherFrame.src, etherFrame.dst, inPort))
            #self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)
        elif arpPacket.opcode == 2:

            self.logger.info("ARP reply recvd")
            eth_pkt = packet.get_protocol(ethernet)
            dst = eth_pkt.dst
            src = eth_pkt.src
            eth_type = eth_pkt.ethertype
            self.logger.info(src)

            
            db0[dpidToIp[str(datapath.id)]]["nbrMac"]=src
            db0[dpidToIp[str(datapath.id)]]["dpid"]=datapath.id
            db0[dpidToIp[str(datapath.id)]]["nbrPort"]=inPort
            self.logger.info(db0)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            IPV4_DST = ip_pkt.dst
            dst_ip = ip_pkt.dst
            IPV4_SRC = ip_pkt.src
            self.logger.info()
            
        
