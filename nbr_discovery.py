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
import ctypes
import os


# variables declared here for new topology

db0={"60.0.0.1":{},'70.0.0.1':{},'80.0.0.1':{}, '90.0.0.1':{}}
db1={}
mobile_db=[]
dpidToIp={'147534647813704':'60.0.0.1',
            '55078337627976':'70.0.0.1',
            '99722776018242':'80.0.0.1',
            '240020097669959':'90.0.0.1'}

ipToNbr={'60.0.0.1':'60.0.0.2','70.0.0.1':'70.0.0.2','80.0.0.1':'80.0.0.2','90.0.0.1':'90.0.0.2'}
fakeMac="aa:aa:aa:aa:aa:aa"

rloc_counter={"60.0.0.1":-1,'70.0.0.1':-1,'80.0.0.1':-1, '90.0.0.1':-1}

dpidToMac={'147534647813704':'86:2e:96:46:66:48',
            '55078337627976':'32:17:ec:bf:c7:48',
            '99722776018242':'5a:b2:84:a3:fd:42',
            '240020097669959':'da:4c:08:a9:1b:47'}

mobility_detect_ip="127.0.0.1"
IDLE_TIMEOUT=30
HARD_TIMEOUT=0


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

    def dpid_to_mac(self, dpid):
        pass


    def int32_to_uint32(self, i):
        """convert from signed int to unsigned int"""
        return ctypes.c_uint32(i).value

    def tos_to_dst_dscp(self, tos):
        """"""
        multiplier=self.int32_to_uint32(28) #identitiy of bit 456
        tos=tos & multiplier
        dst_dscp=tos >> 2
        return dst_dscp

    def tos_to_src_dscp(self, tos):
        """"""
        multiplier=self.int32_to_uint32(224) #identitiy of bit 123
        tos=tos & multiplier
        src_dscp=tos >> 5
        return src_dscp

    def generate_dscp(self, src_dscp, dst_dscp):
        """"""
        src_dscp=src_dscp << 3
        return src_dscp + dst_dscp


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
        #self.logger.info("nbr discovery process starts")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        xtr_ip=dpidToIp[str(datapath.id)]
        nbr_ip=ipToNbr[xtr_ip]
        #self.logger.info(datapath.id)
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

        #self.logger.info("packet in DPID:%s src_mac:%s dst_mac:%s in_port:%s", DPID, src_mac, dst_mac,  in_port)
        #self.logger.info("Ether Type %s", eth_type)



        # if not arp or ip packet drop
        if eth_type!=0x0800 and eth_type!=0x0806:
            #self.logger.info("drop packet of ether_type: %s",eth_type)
            return 0

        if eth_type==0x0800:
            #self.logger.info("controller recieved IP packet")
            ip_pkt = packet.get_protocol(ipv4.ipv4)
            p_ipv4_src = ip_pkt.src
            p_ipv4_dst = ip_pkt.dst

            if p_ipv4_dst == mobility_detect_ip:
                self.logger.info("Mobility notification detected")
                p_tos=ip_pkt.tos
                #self.logger.info("preprocessing tos: %s",str(p_tos))
                dst_dscp=self.tos_to_dst_dscp(p_tos)
                src_dscp=self.tos_to_src_dscp(p_tos)

                #src_dscp=self.tos_to_src_dscp(p_tos)
                #self.logger.info("calculated dst dscp: %s",str(dst_dscp))
                #self.logger.info("calculated src dscp: %s",str(src_dscp))
                #delete flow entries on itr with old mappings

                self.delete_old_mapping_itr(ev, p_ipv4_src, src_dscp, dst_dscp)
                return 0



            if p_ipv4_src not in db1:
                #self.logger.info("New host activated from IP")
                self.host_discovery(DPID, p_ipv4_src, src_mac, in_port)
                return 0

            # check for mobility:
            if p_ipv4_src in db1 and db1[p_ipv4_src]["rloc"] != dpidToIp[str(DPID)]:
                self.logger.info("Host %s is Mobile",p_ipv4_src)
                #self.logger.info("Previous RLOC: %s",db1[p_ipv4_src]["rloc"])
                #self.logger.info("Current RLOC: %s",dpidToIp[str(DPID)])
                self.mobility_event(ev)
                return 0    

            if ip_pkt.src in db1 and ip_pkt.dst in db1:
                #self.logger.info("Adding flow for IP packet")
                if db1[ip_pkt.src]['rloc']==db1[ip_pkt.dst]['rloc']:
                    self.logger.info("dropping ip packet for hosts in same rloc: %s", db1[ip_pkt.src]['rloc'])
                    return 0

                self.xtr_flow_entry(ev)

            #return 0s

        if eth_type==0x0806:
            # arp packet    
            arp_pkt = packet.get_protocol(arp)
            p_ipv4_src = arp_pkt.src_ip
            p_ipv4_dst = arp_pkt.dst_ip
            #self.logger.info("packet in recv ")


        # hook for neighbor discovery
        # if arp packet and dst_mac is fakeMac then reply from nbr router
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            eth_pkt = packet.get_protocol(ethernet)
            dst = eth_pkt.dst
            if dst == fakeMac:
                #self.logger.info("ARP reply from nbr router")
                self.receive_arp(dp, packet, etherFrame, in_port)
                return 0

        

        
        

        # hook for host discovery
        if p_ipv4_src not in db1:
            #self.logger.info("New host activated through arp")
            self.host_discovery(DPID, p_ipv4_src, src_mac, in_port)
            return 0

        elif p_ipv4_src in db1 and db1[p_ipv4_src]["rloc"] != dpidToIp[str(DPID)]:
            self.logger.info("Host %s is Mobile",p_ipv4_src)
            #self.logger.info("Previous RLOC: %s",db1[p_ipv4_src]["rloc"])
            #self.logger.info("Current RLOC: %s",dpidToIp[str(DPID)])
            # mobility TBD
            self.mobility_event(ev)

            return 0

        elif p_ipv4_src in db1 and p_ipv4_dst not in db1:
            self.logger.info("\nSource %s registered but Destination %s does not exist\n", p_ipv4_src,p_ipv4_dst)
            #add flow to drop packet
            #self.logger.info("Add 1 priority flow on iTR to drop packets for EID: %s",p_ipv4_dst)
            itr_datapath=dp
            """
            match = ofp_parser.OFPMatch(
                in_port=in_port,
                eth_type=0x0800,#ip packet
                ipv4_dst=p_ipv4_dst,
                )
            actions = [ofp_parser.OFPActionOutput(in_port,
                ofp.OFPCML_NO_BUFFER,),]

            self.add_flow(itr_datapath, 1, match, actions)
            """
            # hard timeout TBD
            match = ofp_parser.OFPMatch(
                in_port=in_port,
                eth_type=0x0806,#arp packet
                arp_tpa=p_ipv4_dst,
                )

            actions = [ofp_parser.OFPActionOutput(in_port,
                ofp.OFPCML_NO_BUFFER,),]

            #self.add_flow(itr_datapath, 1, match, actions)
            
        #elif p_ipv4_src in db1 and db1[p_ipv4_src]["rloc"] == dpidToIp[str(DPID)]:
            #self.logger.info("Host %s is not mobile",p_ipv4_src)

        

        #self.logger.info("SRC_IP:%s", IPV4_SRC)


        # if arp packet and ipv4_dst and ipv4_src is a registered host and same rloc then reply for arp with host_mac
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            eth_pkt = packet.get_protocol(ethernet)
            if p_ipv4_dst in db1 and p_ipv4_src in db1:
                if db1[p_ipv4_src]['rloc']==db1[p_ipv4_dst]['rloc']:
                    self.logger.info("\nARP request for host in same rloc : %s",p_ipv4_dst)
                    arp_src_mac=db1[p_ipv4_dst]['host_mac']
                    arp_src_ip=p_ipv4_dst
                    arp_dst_mac=src_mac
                    arp_dst_ip=p_ipv4_src
                    arp_out_port=in_port
                    self.reply_arp(dp, arp_src_mac, arp_src_ip, arp_dst_mac, arp_dst_ip, in_port)
                    return 0

        # if arp packet and ipv4_dst and ipv4_src is a registered host then reply for arp
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            eth_pkt = packet.get_protocol(ethernet)
            if p_ipv4_dst in db1 and p_ipv4_src in db1:
                #self.logger.info("\nARP request for valid lisp host : %s",p_ipv4_dst)
                arp_src_mac=db1[p_ipv4_src]["nbr_rtr_mac"]
                arp_src_ip=p_ipv4_dst
                arp_dst_mac=src_mac
                arp_dst_ip=p_ipv4_src
                arp_out_port=in_port
                self.reply_arp(dp, arp_src_mac, arp_src_ip, arp_dst_mac, arp_dst_ip, in_port)

                #calling module to add flow entries on xTRs
                #self.xtr_flow_entry(ev)
                return 0

            #else:
                #self.logger.info("ARP request for invalid lisp host: %s", p_ipv4_dst)
                #self.logger.info("dst ip: %s",p_ipv4_dst)        
                #reply_arp(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
                #self.logger.info(ipv4_dst)
                

        
        
        
    def host_discovery(self, DPID, ipv4_src, src_mac, in_port):

        if ipv4_src in db0:
            self.logger.info("\n\nRLOC %s discovery as host rejected ",ipv4_src)
            return 0
        #self.logger.info("host discovery process starts")
        #self.logger.info("adding entry into db1")
        rloc_counter[dpidToIp[str(DPID)]] += 1
        db1[ipv4_src]={"netmask":32,"rloc":dpidToIp[str(DPID)],"host_mac":src_mac,
                        "nbr_rtr_mac":db0[dpidToIp[str(DPID)]]["nbr_mac"],
                        "xtr_port":in_port,
                        "nbr_rtr_port":db0[dpidToIp[str(DPID)]]["nbr_rtr_port"],
                        "dscp_id":rloc_counter[dpidToIp[str(DPID)]]}
        self.logger.info("\nHost discovered : %s",ipv4_src)         
        #self.logger.info("rloc-counter:")                
        #self.logger.info(rloc_counter)
        self.logger.info(pprint(db1))


    def mobility_event(self, ev):
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

        self.logger.info("\nExecuting mobility function")

        if eth_type==0x0800:
            #self.logger.info("controller recieved IP packet")
            ip_pkt = packet.get_protocol(ipv4.ipv4)
            p_ipv4_src = ip_pkt.src
            p_ipv4_dst = ip_pkt.dst

        elif eth_type==0x0806:
            # arp packet    
            arp_pkt = packet.get_protocol(arp)
            #self.logger.info("controller recieved ARP packet")
            p_ipv4_src = arp_pkt.src_ip
            p_ipv4_dst = arp_pkt.dst_ip

        self.logger.info("Previous RLOC: %s",db1[p_ipv4_src]["rloc"])
        self.logger.info("Current RLOC: %s",dpidToIp[str(DPID)])

        prev_rloc = db1[p_ipv4_src]["rloc"]
        curr_rloc = dpidToIp[str(DPID)]

        #self.logger.info("deleting flow entry on previous rloc")

        self.delete_flow_entry_prev_xtr(ev, prev_rloc, p_ipv4_src)

        #self.logger.info("add flow entry on prev rloc to notify controller")


        self.add_flow_entry_prev_xtr(ev, prev_rloc, p_ipv4_src)

        #move mobile device info to mobile_db
        mobile_device_ip=p_ipv4_src

        for key, value in db1.iteritems():
            if key==mobile_device_ip:
                value['mobile_ip']=key
                mobile_db.append(value)

        #mobile_db[mobile_device_ip]=db1[mobile_device_ip]
        del db1[mobile_device_ip]
        
        self.logger.info("Updated mobile db:")
        self.logger.info(pprint(mobile_db))

        #mobile host discovery => mapping with new rloc

        new_dpid = db0[curr_rloc]["dpid"]

        #self.logger.info("mobile host discovery; adding new db1 entry")
        self.host_discovery(new_dpid, mobile_device_ip, src_mac, in_port)

        return 0




    def add_flow_entry_prev_xtr(self, ev, prev_rloc, mobile_device_ip):
        msg = ev.msg

        
        self.logger.info("\n\nAdding mobility flow on prev xtr: %s", prev_rloc)
        datapath=db0[prev_rloc]["xtr_datapath"]
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        # sending 8 flow addcommands for every possible source dscp id
        for i in range(0,8):
            dscp_id=self.generate_dscp(i,db1[mobile_device_ip]["dscp_id"])
            match = ofp_parser.OFPMatch(
                eth_type=0x0800,
                ip_dscp=dscp_id,
                in_port=db0[prev_rloc]["nbr_rtr_port"],
                ipv4_dst=prev_rloc
                )
            actions = [ofp_parser.OFPActionSetField(
                    ipv4_dst=mobility_detect_ip),
                  ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                    ofp.OFPCML_NO_BUFFER)]

            self.add_flow(datapath, 20, match, actions)
        


    def delete_flow_entry_prev_xtr(self,ev, prev_rloc, mobile_device_ip):
        msg = ev.msg

        self.logger.info('\n\nDeleting flow entry on prev xtr: %s', prev_rloc)
        # tbd
        # deleting egress flow from core to xtr
        datapath=db0[prev_rloc]["xtr_datapath"]
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # sending 8 flow delete commands for every possible source dscp id
        for i in range(0,8):
            dscp_id=self.generate_dscp(i,db1[mobile_device_ip]["dscp_id"])
            match = ofp_parser.OFPMatch(
                eth_type=0x0800,
                ip_dscp=dscp_id,
                in_port=db0[prev_rloc]["nbr_rtr_port"],
                )
            mod = ofp_parser.OFPFlowMod(datapath=datapath, table_id=0, cookie=1,
                command=ofp.OFPFC_DELETE,out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, 
                priority=20, match=match)
            datapath.send_msg(mod)
        
        
        # deleting ingress flow from xtr to core since device has moved
        match = ofp_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=mobile_device_ip,
            in_port=db1[mobile_device_ip]["xtr_port"],
            )
        mod = ofp_parser.OFPFlowMod(datapath=datapath, table_id=0, cookie=1,
            command=ofp.OFPFC_DELETE,out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, 
            priority=20, match=match)
        datapath.send_msg(mod)
        

    def delete_old_mapping_itr(self,ev, p_ipv4_src, src_dscp, dst_dscp):
        self.logger.info("\n\nDeleting old mapping on itr")

        # datapath of xtr that had old mapping for mobile host
        itr_old_mapping_datapath=db0[p_ipv4_src]["xtr_datapath"]
        ofp = itr_old_mapping_datapath.ofproto
        ofp_parser = itr_old_mapping_datapath.ofproto_parser    


        msg = ev.msg



        # datapath of xtr that generatred mobility notification
        prev_xtr_datapath=msg.datapath 

        # ip address of xtr that generatred mobility notification
        prev_xtr_ip=dpidToIp[str(prev_xtr_datapath.id)] 

        # ip address of xtr that has old mapping
        itr_old_mapping_ip=p_ipv4_src

       
        # retreive mobile device ip address from dscp bit through mobile_db

        #self.logger.info('old mapping rloc: %s',p_ipv4_src)
        #self.logger.info('dst_dscp: %s',dst_dscp)
        

        #self.logger.info('previous xtr IP: %s %s',prev_xtr_ip, type(prev_xtr_ip))
        

        for item in mobile_db:
            if item['rloc']==prev_xtr_ip and item['dscp_id']==int(dst_dscp):
                mobile_device_ip=item['mobile_ip']  
                self.logger.info("\n\nip address of mobile device: %s",mobile_device_ip)
                break 

        """
        for key, value in mobile_db.iteritems():
            #self.logger.info('inside for loop: key: %s value: %s',key,value)
            if value['rloc']==prev_xtr_ip and value['dscp_id']==int(dst_dscp):
                self.logger.info("ip address of mobile device: %s",key)
                mobile_device_ip=key  
        """

        for key, value in db1.iteritems():
            #self.logger.info('inside for loop: key: %s value: %s',key,value)
            if value['rloc']==p_ipv4_src and value['dscp_id']==int(src_dscp):
                #self.logger.info("ip address of source device: %s",key)
                source_device_ip=key
                break 

        #self.logger.info('Source device ip %s',source_device_ip)            

        # deleting ingress flow entry on old mapping xtr

        match = ofp_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=source_device_ip,
            ipv4_dst=mobile_device_ip,
            in_port=db1[source_device_ip]['xtr_port'],
            )
        mod = ofp_parser.OFPFlowMod(datapath=itr_old_mapping_datapath, table_id=0, cookie=1,
            command=ofp.OFPFC_DELETE,out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, 
            priority=20, match=match)
        itr_old_mapping_datapath.send_msg(mod)

                
                
        # deleting egress flow entry on old mapping xtr

        dscp_id=self.generate_dscp(dst_dscp,src_dscp)
        #self.logger.info('dscp id for deleting egress flow on old mapping xtr: %s',dscp_id)
        match = ofp_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=prev_xtr_ip,
            ipv4_dst=itr_old_mapping_ip,
            ip_dscp=int(dscp_id),
            in_port=db0[p_ipv4_src]["nbr_rtr_port"],
            )
        mod = ofp_parser.OFPFlowMod(datapath=itr_old_mapping_datapath, table_id=0, cookie=1,
            command=ofp.OFPFC_DELETE,out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, 
            priority=20, match=match)
        itr_old_mapping_datapath.send_msg(mod)
        



 
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
        """
        if eth_type==0x0806:
            # arp packet
            arp_pkt = packet.get_protocol(arp)
            p_ipv4_src = arp_pkt.src_ip
            p_ipv4_dst = arp_pkt.dst_ip
        """

        if eth_type==0x0800:
            # IP packet
            ip_pkt = packet.get_protocol(ipv4.ipv4)
            p_ipv4_src = ip_pkt.src
            p_ipv4_dst = ip_pkt.dst


        self.logger.info('\n\n %s sending packets to %s ', p_ipv4_src, p_ipv4_dst)

        # adding iTR flow entry on source rloc
        self.logger.info("Adding iTR flow entry on source rloc: %s",db1[p_ipv4_src]["rloc"])

        #itr dpid extracted from packet in current datapath

        itr_datapath=dp

        # calculating dscp_id from source and dest dscp id
        src_dscp_id=db1[p_ipv4_src]["dscp_id"]
        dst_dscp_id=db1[p_ipv4_dst]["dscp_id"]

        # forward dscp_id is from rloc1 host to rloc2 destination
        p_dscp_id_forward=self.generate_dscp(src_dscp_id,dst_dscp_id)


        match = ofp_parser.OFPMatch(
            in_port=inPort,
            eth_type=0x0800,
            ipv4_src=p_ipv4_src,
            ipv4_dst=p_ipv4_dst,
            #ip_dscp=0,
            #ip_ecn=0,
            )
        #self.logger.info("forward dscp_id: %s", p_dscp_id_forward)
        #self.logger.info("rloc2 id: %s",db1[p_ipv4_dst]["rloc"])

        actions = [ofp_parser.OFPActionSetField(
                eth_src=db0[db1[p_ipv4_src]["rloc"]]["xtr_mac"],),
              ofp_parser.OFPActionSetField(
                ipv4_src=db1[p_ipv4_src]["rloc"]),
              ofp_parser.OFPActionSetField(
                ipv4_dst=db1[p_ipv4_dst]["rloc"]),
              ofp_parser.OFPActionSetField(
                ip_dscp=p_dscp_id_forward),
              #ofp_parser.OFPActionSetField(
                #ip_ecn=0),
              ofp_parser.OFPActionOutput(db1[p_ipv4_src]["nbr_rtr_port"],
                                  ofp.OFPCML_NO_BUFFER,),]

        self.add_flow(itr_datapath, 20, match, actions)

        #self.add_flow(itr_datapath, 20, match, actions)


        # adding eTR flow entry on dest rloc
        self.logger.info("Adding eTR flow entry on destination rloc: %s",db1[p_ipv4_dst]["rloc"])
        #etr dpid extracted from db0
        etr_datapath=db0[db1[p_ipv4_dst]["rloc"]]["xtr_datapath"]
        match = ofp_parser.OFPMatch(
            in_port=db0[db1[p_ipv4_dst]["rloc"]]["nbr_rtr_port"],
            eth_type=0x0800,
            ipv4_src=db1[p_ipv4_src]["rloc"],
            ipv4_dst=db1[p_ipv4_dst]["rloc"],
            ip_dscp=p_dscp_id_forward,
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
        mod = parser.OFPFlowMod(datapath=datapath,
                                idle_timeout=IDLE_TIMEOUT,
                                hard_timeout=HARD_TIMEOUT,
                                priority=priority,
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
            #self.logger.info("receive ARP request %s => %s (port%d)"
                       #%(etherFrame.src, etherFrame.dst, in_port))
            #self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, in_port)
        elif arpPacket.opcode == 2:

            #self.logger.info("ARP reply recvd")
            eth_pkt = packet.get_protocol(ethernet)
            dst = eth_pkt.dst
            src = eth_pkt.src
            eth_type = eth_pkt.ethertype
            #self.logger.info(src)
            #self.logger.info(arpPacket.src_ip)
            
            db0[dpidToIp[str(datapath.id)]]["nbr_mac"]=src
            db0[dpidToIp[str(datapath.id)]]["dpid"]=datapath.id
            db0[dpidToIp[str(datapath.id)]]["nbr_rtr_port"]=in_port
            db0[dpidToIp[str(datapath.id)]]["xtr_datapath"]=datapath
            db0[dpidToIp[str(datapath.id)]]["xtr_mac"]=dpidToMac[str(datapath.id)]
            rloc_counter[dpidToIp[str(datapath.id)]]=0

            
            #self.logger.info(pprint(db0))
            self.logger.info("RLOC discovery complete: %s\n\n",dpidToIp[str(datapath.id)])
            self.logger.info('Setting arp entry for rloc')
            cmd="sudo arp -s "+dpidToIp[str(datapath.id)]+' '+dpidToMac[str(datapath.id)]
            self.logger.info('command: %s', cmd)
            os.system(cmd)
            #for p in packet.protocols:
            #    print p

    def resolve_arp_xtr(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        #self.logger.info("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))

    def reply_arp(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
        """dstIp = arpPacket.src_ip
            srcIp = arpPacket.dst_ip
            dstMac = etherFrame.src"""
        

        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        #self.logger.info("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))
