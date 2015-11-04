#!/usr/bin/python
#coding=utf-8

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib import mac
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.base import app_manager
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin
from netaddr import *
import Queue #Libreria de cola
import ipaddr
import ipaddress

class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    #Tabla de enrutamiento estatito
    ip_mac_port = {1: ('255.255.255.0','00:00:00:00:01:01','192.168.1.1'),
               2: ('255.255.255.0','00:00:00:00:01:02','192.168.2.1'),
               3: ('255.255.255.0','00:00:00:00:01:03','192.168.3.1'),
               4: ('255.255.255.0','00:00:00:00:01:04','192.168.4.1')}
    tabla_enrutamiento = {}
    colaespera = [] #Atributo que guarda la cola
    
    #  Inserta una entrada a la tabla de flujo.
   
    def compare(self,MASK_LIST):
		cont=0
		maximo=0
		port=0
		for MASK in MASK_LIST:
			for i in range(len(MASK[0])):
				if(MASK[0][i]=='1'):
					cont=cont+1
			if(cont>maximo):
				maximo=cont
				port=MASK[1]
				
		return port
   
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match,
                instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                match=match, instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
        print(mod)
        datapath.send_msg(mod)
        
    def ARPREQUESTPacket(self,dest_ip,source_ip,port,datapath):
        print port
        #if (self.ip_mac_port[in_port][2]==arp_msg.dst_ip and arp_msg.opcode==arp.ARP_REQUEST):
        e = ethernet.ethernet(dst=mac.BROADCAST_STR ,
                      src=self.ip_mac_port.get(port)[1],
                      ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REQUEST,
                src_mac=self.ip_mac_port.get(port)[1], src_ip=source_ip, dst_ip=dest_ip)
        
        
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        self.send_packet(datapath, port,p)

    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                  buffer_id=ofproto.OFP_NO_BUFFER,
                  in_port=ofproto.OFPP_CONTROLLER,
                  actions=actions,
                  data=data)
        datapath.send_msg(out)

    def ARPPacket(self,arp_msg,in_port,datapath):
        if (self.ip_mac_port[in_port][2]==arp_msg.dst_ip and arp_msg.opcode==arp.ARP_REQUEST):
            e = ethernet.ethernet(dst=arp_msg.src_mac,
                          src=self.ip_mac_port[in_port][1],
                          ethertype=ether.ETH_TYPE_ARP)
            a = arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=self.ip_mac_port[in_port][1], src_ip=arp_msg.dst_ip,
                    dst_mac=arp_msg.src_mac, dst_ip=arp_msg.src_ip)
            p = packet.Packet()
            p.add_protocol(e)
            p.add_protocol(a)
            self.send_packet(datapath, in_port,p)
        #Procesar un ARPReply para hacer enrutamiento
        elif arp_msg.opcode==arp.ARP_REPLY:
            for paquetes in self.colaespera: #Buscamos en la lista para ver si hay paquetes en espera
                pkt_ipv4=paquetes.get_protocol(ipv4.ipv4) 
                if(pkt_ipv4):
                    if (pkt_ipv4.dst==arp_msg.src_ip): #Si la ip de destino del paquete coincide con quien envio esa ip
                        self.tabla_enrutamiento[pkt_ipv4.dst]=arp_msg.src_mac
                        #self.ReenvioPro(self,datapath,pkt_ipv4.dst,in_port,self.ip_mac_port[in_port][1],arp_msg.src_mac,paquetes)
                        #self.IPPACKET(datapath,in_port,arp_msg.src_mac,paquetes )
                        self.colaespera.remove(paquetes)
                        ofproto = datapath.ofproto
                        ofp_parser = datapath.ofproto_parser
                        actions =[ofp_parser.OFPActionSetField(eth_dst=self.tabla_enrutamiento[pkt_ipv4.dst]),
                                      ofp_parser.OFPActionSetField(eth_src=self.ip_mac_port.get(in_port)[1]),
                                      ofp_parser.OFPActionDecNwTtl(),
                                      ofp_parser.OFPActionOutput(in_port)]
                        
                        
                        paquetes.serialize()
                        data = paquetes.data
        #port)]
                        out = ofp_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
                        datapath.send_msg(out)


                        
    def ICMPPacket(self, datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
            eer=ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                        dst=pkt_ethernet.src,
                        src=self.ip_mac_port[in_port][1])
                        
            iper=ipv4.ipv4(dst=pkt_ipv4.src,
                    src=self.ip_mac_port[in_port][2],
                    proto=pkt_ipv4.proto)
                    
            icmper=icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                    code=icmp.ICMP_ECHO_REPLY_CODE,
                    csum=0,
                    data=pkt_icmp.data)
            p = packet.Packet()
            p.add_protocol(eer)
            p.add_protocol(iper)
            p.add_protocol(icmper)
    
            self.send_packet(datapath, in_port, p)
            
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    
    def packet_in_handler(self, ev):
      
        msg = ev.msg               # Objeto que representa la estuctura de datos PacketIn.
        datapath = msg.datapath    # Identificador del datapath correspondiente al switch.
        ofproto = datapath.ofproto # Protocolo utilizado que se fija en una etapa 
                                   # de negociacion entre controlador y switch

        ofp_parser=datapath.ofproto_parser # Parser con la version OF
                       # correspondiente

        in_port = msg.match['in_port'] # Puerto de entrada.
        #print(in_port)

        # Ahora analizamos el paquete utilizando las clases de la libreria packet.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        print("Oh is a packet!")
        #print(eth);
        if eth.ethertype==0x0800: #Si es IP
            comprobacion=0 
            print("Wow an IP packet packet!")
            pkt_ipv4=pkt.get_protocol(ipv4.ipv4)
            entradas_router = self.ip_mac_port.keys()
            for entradas in entradas_router :
                if self.ip_mac_port.get(entradas)[2]==pkt_ipv4.dst:  #Si es para el ROUTER
                    print("A packet for me :D")
                    pkt_icmp=pkt.get_protocol(icmp.icmp)
                    comprobacion=1
                    if pkt_icmp: #Si es ICMP
                        print("I will answer that ICMP e_e")
                        self.ICMPPacket(datapath, in_port, eth, pkt_ipv4, pkt_icmp)
            if comprobacion==0:
                listacoincide=[]
                for entradas in entradas_router :
                    if  ipaddr.IPv4Address(pkt_ipv4.dst) in  ipaddr.IPv4Network(self.ip_mac_port.get(entradas)[2]+"/"+ self.ip_mac_port.get(entradas)[0]):
                        mask=IPAddress(self.ip_mac_port.get(entradas)[0]).bin
                        listacoincide.append((mask,entradas))
                        
                entradas=self.compare(listacoincide)
                if(pkt_ipv4.src not in self.tabla_enrutamiento): 
                    self.tabla_enrutamiento[pkt_ipv4.src]=eth.src
                if(pkt_ipv4.dst not in self.tabla_enrutamiento):
                    print("I don't know that mac :c")
                    self.colaespera.append(pkt)
                    self.ARPREQUESTPacket(pkt_ipv4.dst,pkt_ipv4.src,entradas,datapath)
                else: #Si tenemos la mac en cache
                    #self.ReenvioPro(datapath, entradas, pkt_ipv4.dst, self.ip_mac_port[entradas][1], self.tabla_enrutamiento[ipv4], pkt)
                    print entradas
                    print("I will flow that")
                    #print self.tablaenrutamiento(pkt_ipv4.dst)
                    actions =[ofp_parser.OFPActionSetField(eth_dst=self.tabla_enrutamiento[pkt_ipv4.dst]),
                              ofp_parser.OFPActionSetField(eth_src=self.ip_mac_port.get(entradas)[1]),
                              ofp_parser.OFPActionDecNwTtl(),
                              ofp_parser.OFPActionOutput(entradas)]

                    match = ofp_parser.OFPMatch(ipv4_dst=pkt_ipv4.dst,eth_type=ether.ETH_TYPE_IP)
                    #inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    self.add_flow( datapath=datapath, priority=0, match=match, actions=actions, buffer_id=msg.buffer_id)
                    #out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions,data=msg.data)
                    #datapath.send_msg(pkt)
        
        elif eth.ethertype==ether.ETH_TYPE_ARP: #Si es ARP
                pkt_arp=pkt.get_protocol(arp.arp)
                self.ARPPacket(pkt_arp,in_port,datapath)