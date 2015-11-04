#!/usr/bin/python
#coding=utf-8
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.base import app_manager
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin

class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    mac_to_port = dict()
    
    def __init__(self, *args, **kwargs):
        super(L2Forwarding, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg               # Objeto que representa la estuctura de datos PacketIn.
        datapath = msg.datapath    # Identificador del datapath correspondiente al switch.
        ofproto = datapath.ofproto # Protocolo utilizado que se fija en una etapa 
                                   # de negociacion entre controlador y switch

        ofp_parser=datapath.ofproto_parser # Parser con la version OF
					   # correspondiente

        in_port = msg.match['in_port'] # Puerto de entrada.

        # Ahora analizamos el paquete utilizando las clases de la libreria packet.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Extraemos la MAC de destino

        dst = eth.dst  
        
        #Extramos la MAC de origen
        
        src = eth.src

	if src not in self.mac_to_port.keys():
		self.mac_to_port[src]=in_port

	if haddr_to_bin(dst) == mac.BROADCAST or mac.is_multicast(haddr_to_bin(dst)):
		# Creamos el conjunto de acciones: FLOOD
		actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

		# Ahora creamos el match  
		# fijando los valores de los campos 
		# que queremos casar.
		match = ofp_parser.OFPMatch(eth_dst=dst)

		# Creamos el conjunto de instrucciones.
		inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

		# Creamos el mensaje OpenFlow 
		mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, idle_timeout=30, buffer_id=msg.buffer_id)

		# Enviamos el mensaje.
		datapath.send_msg(mod)

	elif dst not in self.mac_to_port.keys():
		actions = [ofp_parser.OFPPacketOut(ofproto.OFPP_FLOOD)]
		req = ofp_parser.OFPPacketOut(datapath, msg.buffer_id, in_port, actions, data=msg.data)
		datapath.send_msg(req)

	else :
		actions = [ofp_parser.OFPActionOutput(self.mac_to_port[dst])]

		# Ahora creamos el match  
		# fijando los valores de los campos 
		# que queremos casar.
		match = ofp_parser.OFPMatch(eth_dst=dst)

		# Creamos el conjunto de instrucciones.
		inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

		# Creamos el mensaje OpenFlow 
		mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, idle_timeout=30, buffer_id=msg.buffer_id)

		# Enviamos el mensaje.
		datapath.send_msg(mod)