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
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.ofproto import ether
from netaddr import IPNetwork, IPAddress


"""db0: nbr discovery
    RLOC, DPID, NBR MAC, o/p port NBR"""


# variables declared here

db0={"3.0.0.1":{},'5.0.0.1':{}}
db1={"1.0.0.10":{}}
dpidToIp={'161442412056386':'3.0.0.1','223103364804175':'5.0.0.1'}
ipToNbr={'3.0.0.1':'3.0.0.2','5.0.0.1':'5.0.0.2'}
fakeMac="aa:aa:aa:aa:aa:aa"
rloc_counter={"3.0.0.1":0,"5.0.0.1":0}
dpidToMac={'161442412056386':'92:d4:bd:9f:4f:42','223103364804175':'ca:e9:4c:ce:ae:4f'}




class ExampleSwitch13(app_manager.RyuApp):
    


    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    
    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)


    def ip_in_subnet(self, ip_address, ip_network, netmask):
        ip_subnet=ip_network+'/'+str(netmask)
        if IPAddress(ip_address) in IPNetwork(ip_subnet):
            self.logger.info("yayy!")
            return True
        else:
            self.logger.info("NAyyy")    
            return False

    def dpid_to_mac(dpid):
        pass


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER
                                          )]
        self.add_flow(datapath, 0, match, actions)
        #self.ip_in_subnet("192.168.1.1","192.168.1.0",24)
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
        self.send_arp(datapath, 1, fakeMac, xtr_ip, "ff:ff:ff:ff:ff:ff", nbr_ip, ofproto.OFPP_FLOOD)

    


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        in_port = msg.match['in_port']
        DPID=dp.id
        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)
        dst_mac = etherFrame.dst
        src_mac = etherFrame.src
        eth_type = etherFrame.ethertype
        #eth_type = eth_pkt.ethertype
        if eth_type==0x0800:
            self.logger.info("controller recieved icmp packet")
            ip_pkt = packet.get_protocol(ipv4.ipv4)
            if ip_pkt.src in db1 and ip_pkt.dst in db1:
                self.logger.info("Adding flow for icmp packet")
                self.xtr_flow_entry(ev)

            return 0
        arp_pkt = packet.get_protocol(arp)
        p_ipv4_src = arp_pkt.src_ip
        p_ipv4_dst = arp_pkt.dst_ip
        self.logger.info("packet in recv ")


        # hook for neighbor discovery
        # if arp packet and dst_mac is fakeMac then reply from nbr router
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            self.logger.info(etherFrame.ethertype)
            eth_pkt = packet.get_protocol(ethernet)
            dst = eth_pkt.dst
            if dst == fakeMac:
                self.receive_arp(dp, packet, etherFrame, in_port)
                return 0

        

        self.logger.info("packet in DPID:%s src_mac:%s dst_mac:%s in_port:%s", DPID, src_mac, dst_mac,  in_port)
        self.logger.info("Ether Type %s", eth_type)
        #eth = pkt.get_protocols(ethernet.ethernet)[0]

        # hook for host discovery
        if p_ipv4_src not in db1:
            self.host_discovery(DPID, p_ipv4_src, src_mac, in_port)
            return 0
        #self.logger.info("SRC_IP:%s", IPV4_SRC)


        # if arp packet and ipv4_dst and ipv4_src is a registered host then reply for arp
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            self.logger.info(etherFrame.ethertype)
            eth_pkt = packet.get_protocol(ethernet)
            if p_ipv4_dst in db1 and p_ipv4_src in db1:
                self.logger.info("ARP request for valid lisp host")
                self.logger.info("dst ip: %s",p_ipv4_dst)
                arp_src_mac=db1[p_ipv4_src]["nbr_rtr_mac"]
                arp_src_ip=p_ipv4_dst
                arp_dst_mac=src_mac
                arp_dst_ip=p_ipv4_src
                arp_out_port=in_port
                self.reply_arp(dp, arp_src_mac, arp_src_ip, arp_dst_mac, arp_dst_ip, in_port)
                #calling module to add flow entries on xTRs
                self.xtr_flow_entry(ev)
                return 0
            else:
                self.logger.info("ARP request for invalid lisp host")
                self.logger.info("dst ip: %s",p_ipv4_dst)        
                #reply_arp(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
                #self.logger.info(ipv4_dst)
                

        
        
         




    def host_discovery(self, DPID, ipv4_src, src_mac, in_port):
        self.logger.info("host discovery process starts")
        self.logger.info("adding entry into db1")
        rloc_counter[dpidToIp[str(DPID)]] += 1
        db1[ipv4_src]={"netmask":32,"rloc":dpidToIp[str(DPID)],"host_mac":src_mac,
                        "nbr_rtr_mac":db0[dpidToIp[str(DPID)]]["nbr_mac"],
                        "xtr_port":in_port,
                        "nbr_rtr_port":db0[dpidToIp[str(DPID)]]["nbr_rtr_port"],
                        "dscp_id":rloc_counter[dpidToIp[str(DPID)]]}
        self.logger.info("rloc-counter:")                
        self.logger.info(rloc_counter)
        self.logger.info(pprint(db1))



    def xtr_flow_entry(self, ev):
        """adds flow entry on both itr and etr 
        for one way traffic"""
        
        #extracting required variables
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        inPort = msg.match['in_port']
        DPID=dp.id
        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)
        dst_mac = etherFrame.dst
        src_mac = etherFrame.src
        eth_type = etherFrame.ethertype
        #eth_type = eth_pkt.ethertype
        if eth_type==0x0806:
            # arp packet
            arp_pkt = packet.get_protocol(arp)
            p_ipv4_src = arp_pkt.src_ip
            p_ipv4_dst = arp_pkt.dst_ip

        if eth_type==0x0800:
            # icmp packet
            ip_pkt = packet.get_protocol(ipv4.ipv4)
            p_ipv4_src = ip_pkt.src
            p_ipv4_dst = ip_pkt.dst

        # adding iTR flow entry on source rloc
        self.logger.info("adding iTR flow entry on source rloc")

        #itr dpid extracted from packet in current datapath

        itr_datapath=dp
        match = ofp_parser.OFPMatch(
            in_port=inPort,
            eth_type=0x0800,
            ipv4_src=p_ipv4_src,
            ipv4_dst=p_ipv4_dst,
            #ip_dscp=0,
            #ip_ecn=0,
            )
        self.logger.info("dscp id: %s", db1[p_ipv4_dst]["dscp_id"])
        self.logger.info("rloc2 id: %s",db1[p_ipv4_dst]["rloc"])

        actions = [ofp_parser.OFPActionSetField(
                eth_src=db0[db1[p_ipv4_src]["rloc"]]["xtr_mac"],),
              ofp_parser.OFPActionSetField(
                ipv4_src=db1[p_ipv4_src]["rloc"]),
              ofp_parser.OFPActionSetField(
                ipv4_dst=db1[p_ipv4_dst]["rloc"]),
              ofp_parser.OFPActionSetField(
                ip_dscp=db1[p_ipv4_dst]["dscp_id"]),
              #ofp_parser.OFPActionSetField(
                #ip_ecn=0),
              ofp_parser.OFPActionOutput(db1[p_ipv4_src]["nbr_rtr_port"],
                                  ofp.OFPCML_NO_BUFFER,),]

        self.add_flow(itr_datapath, 20, match, actions)

        #self.add_flow(itr_datapath, 20, match, actions)


        # adding eTR flow entry on dest rloc
        self.logger.info("adding eTR flow entry on destination rloc")
        #etr dpid extracted from db0
        etr_datapath=db0[db1[p_ipv4_dst]["rloc"]]["xtr_datapath"]
        match = ofp_parser.OFPMatch(
            in_port=db0[db1[p_ipv4_dst]["rloc"]]["nbr_rtr_port"],
            eth_type=0x0800,
            ipv4_src=db1[p_ipv4_src]["rloc"],
            ipv4_dst=db1[p_ipv4_dst]["rloc"],
            ip_dscp=db1[p_ipv4_dst]["dscp_id"],
            )
        actions = [ofp_parser.OFPActionSetField(
                    ipv4_dst=p_ipv4_dst),
                    ofp_parser.OFPActionSetField(
                    ipv4_src=p_ipv4_src),
                    ofp_parser.OFPActionSetField(
                    eth_dst=db1[p_ipv4_dst]["host_mac"]),
                    ofp_parser.OFPActionSetField(
                    ip_dscp=0),
                    ofp_parser.OFPActionOutput(db1[p_ipv4_dst]["xtr_port"],
                    ofp.OFPCML_NO_BUFFER,),]

        self.add_flow(etr_datapath,20,match,actions)




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


    def receive_arp(self, datapath, packet, etherFrame, in_port):
        arpPacket = packet.get_protocol(arp)

        if arpPacket.opcode == 1:
            arp_dstIp = arpPacket.dst_ip
            self.logger.info("receive ARP request %s => %s (port%d)"
                       %(etherFrame.src, etherFrame.dst, in_port))
            #self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, in_port)
        elif arpPacket.opcode == 2:

            self.logger.info("ARP reply recvd")
            eth_pkt = packet.get_protocol(ethernet)
            dst = eth_pkt.dst
            src = eth_pkt.src
            eth_type = eth_pkt.ethertype
            self.logger.info(src)
            #self.logger.info(arpPacket.src_ip)
            
            db0[dpidToIp[str(datapath.id)]]["nbr_mac"]=src
            db0[dpidToIp[str(datapath.id)]]["dpid"]=datapath.id
            db0[dpidToIp[str(datapath.id)]]["nbr_rtr_port"]=in_port
            db0[dpidToIp[str(datapath.id)]]["xtr_datapath"]=datapath
            db0[dpidToIp[str(datapath.id)]]["xtr_mac"]=dpidToMac[str(datapath.id)]
            rloc_counter[dpidToIp[str(datapath.id)]]=0
            
            self.logger.info(pprint(db0))
            #for p in packet.protocols:
            #    print p

    def resolve_arp_xtr(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        self.logger.info("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))

    def reply_arp(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
        """dstIp = arpPacket.src_ip
            srcIp = arpPacket.dst_ip
            dstMac = etherFrame.src"""
        

        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        self.logger.info("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))
