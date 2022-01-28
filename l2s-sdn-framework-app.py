import json
import logging

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.lib import dpid as dpid_lib
from ryu.topology.api import get_switch, get_link, get_host, event
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv6

import networkx as nx


# REST API for switch configuration
#
# get all the switches
# GET /v1.0/topology/switches
#
# get the switch
# GET /v1.0/topology/switches/<dpid>
#
# get all the links
# GET /v1.0/topology/links
#
# get the links of a switch
# GET /v1.0/topology/links/<dpid>
#
# get all the hosts
# GET /v1.0/topology/hosts
#
# get the hosts of a switch
# GET /v1.0/topology/hosts/<dpid>
#
# where
# <dpid>: datapath id in 16 hex


class TopologyAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopologyAPI, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        wsgi.register(TopologyController, {'topology_api_app': self})
        self.mac_to_port = {}  # Dictionary mapping mac addresses to switch ports
        self.logger.setLevel(logging.INFO)
        self.graph = nx.Graph()
        self.topology_api_app = self
        self.switch_port_to_hosts = {}
        self.paths = []
        self.last_cookie = 0
        # Counter for increasing weights in the second flow-path creation
        self.counter = 0

    # Function for adding a flow entry into the switches
    def add_flow(self, datapath, priority, match, actions, cookie=0, buffer_id=None):
        of_proto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(of_proto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # Function for deleting paths. It deletes a flow in a specific switch (datapath) with a specific cookie
    def delete_flow(self, datapath, cookie):
        of_proto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            cookie_mask=0xFFFFFFFFFFFFFFFF,
            table_id=of_proto.OFPTT_ALL,
            command=of_proto.OFPFC_DELETE,
            out_port=of_proto.OFPP_ANY,
            out_group=of_proto.OFPG_ANY
        )
        print("Sending OF command to delete rule...")
        print(mod)
        datapath.send_msg(mod)

    # Function for calculating list of available paths among two nodes
    def calculate_paths(self, src_node, dst_node, weight=None):
        paths = list(nx.shortest_simple_paths(self.graph, src_node, dst_node, weight=weight))
        print("Calculating the available paths")
        return paths

    # TODO: Function to check if the stored path is feasible to still work once a link is down
    def check_feasible_path(self, path_to_check):
        feasible = False
        src_node = path_to_check.get('src')
        dst_node = path_to_check.get('dst')
        checking_path = path_to_check.get('path')
        shortest_simple_paths = self.calculate_paths(src_node, dst_node)

        print('Checking if a path is feasible even after a link down... ')
        print('Path to check: {0}'.format(path_to_check))
        print('Shortest simple paths to check: {0}'.format(shortest_simple_paths))

        # Check if any of the calculated paths matches with the stored one. If math, the path is still feasible
        # To check if a path is still feasible, it should be checked all the paths just to not ignored that the
        # shortest path between two nodes is different due to
        if isinstance(shortest_simple_paths, list):
            # It is a list of lists
            for item in shortest_simple_paths:
                if item == checking_path:
                    feasible = True
        else:
            # There is only one path obtained
            if shortest_simple_paths == checking_path:
                feasible = True

        if feasible:
            print("The stored path still is feasible. Do not change it!")
        else:
            print("The stored path is not feasible anymore! Creating a new one...")

        return feasible

    # Function for establishing the OF rules and connect sites
    # TODO: (save the list of paths and the associated cookie, done) and check this info before adding a new one
    def create_flowpath(self, list_available_paths, cookie=None):

        # The cookie arguments allows to modify/update a stored path and maintain that cookie

        self.logger.info("-- List of available paths: %s", list_available_paths)
        # Selects the shortest simple path from the available paths.
        # ensure that there is a list a lists with different paths. Otherwise, the list of available paths
        # is the own path to be selected
        if isinstance(list_available_paths[0], list):
            selected_path = list_available_paths[0]
        else:
            selected_path = list_available_paths
        # Selects the longest simple path from the available paths
        # selected_path = list_available_paths[len(list_available_paths) - 1]
        self.logger.info("- Selected path from the available paths: %s", selected_path)

        if cookie is None:
            # To avoid selecting cookies already used, use the length+1 of the list storing the defined paths
            self.last_cookie = selected_cookie = self.last_cookie + 1
        else:
            selected_cookie = cookie

        path_to_store = {"cookie": selected_cookie,
                         "src": selected_path[0],
                         "dst": selected_path[len(selected_path) - 1],
                         "path": selected_path}
        self.paths.append(path_to_store)
        # Messages for debugging: Delete
        print("-----> Stored path: {0}".format(self.paths))

        # Information that could be read from a file since it is given by the MANO entity
        if selected_cookie == 1:
            port_sw_a_to_host = 1
            port_sw_c_to_host = 1
            mac_host_a = "fa:16:3e:7a:cd:0f"
            mac_host_c = "fa:16:3e:cd:52:83"
        else:
            port_sw_a_to_host = 4
            port_sw_c_to_host = 4
            mac_host_a = "fa:16:3e:ef:33:81"
            mac_host_c = "fa:16:3e:4f:25:26"

        # Go through the elements of the selected path to install the appropriate OF rules
        for i in selected_path:
            datapath = self.graph.nodes[i]["datapath"]
            ofproto = datapath.ofproto
            ofproto_parser = datapath.ofproto_parser

            if selected_path.index(i) == 0:
                print("*** First element of the selected path: {0}".format(i))
                print("*** Next element of the selected path: {0}".format(selected_path[selected_path.index(i) + 1]))
                # First element, install OF rules considering the MAC addresses

                # Dictionary with the info of the link between the first switch and the next switch
                data_info = self.graph.get_edge_data(i, selected_path[selected_path.index(i) + 1])
                out_port = data_info.get('port_dpid_' + str(i))

                # First rule: steer traffic from the connected host to the following switch/hop
                print("** First rule: steer traffic in switch {0} with mac addr src {1} through port {2}".
                      format(i, mac_host_a, out_port))
                self.logger.info("* Installing rule in the dpid %s", i)
                match = ofproto_parser.OFPMatch(eth_src=mac_host_a)
                actions = [ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 125, match, actions, selected_cookie)

                # Second rule: steer traffic to the connected host
                out_port = port_sw_a_to_host
                print("** Second rule: steer traffic in switch {0} with mac addr src {1} through port {2}".
                      format(i, mac_host_c, out_port))
                self.logger.info("* Installing rule in the dpid %s", i)
                match = ofproto_parser.OFPMatch(eth_src=mac_host_c)
                actions = [ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 125, match, actions, selected_cookie)

            elif selected_path.index(i) == len(selected_path) - 1:
                # Last element, install OF rules considering the MAC addresses
                print("*** Last element of the selected path: {0}".format(i))

                # Dictionary with the info of the link between the last switch and the previous switch
                data_info = self.graph.get_edge_data(i, selected_path[selected_path.index(i) - 1])
                out_port = data_info.get('port_dpid_' + str(i))

                print("** First rule: steer traffic in switch {0} with mac addr src {1} through port {2}".
                      format(i, mac_host_c, out_port))
                self.logger.info("* Installing rule in the dpid %s", i)
                match = ofproto_parser.OFPMatch(eth_src=mac_host_c)
                actions = [ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 125, match, actions, selected_cookie)

                out_port = port_sw_c_to_host
                print("** Second rule: steer traffic in switch {0} with mac addr src {1} through port {2}".
                      format(i, mac_host_a, out_port))
                self.logger.info("* Installing rule in the dpid %s", i)
                match = ofproto_parser.OFPMatch(eth_src=mac_host_a)
                actions = [ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 125, match, actions, selected_cookie)

            else:
                # Intermediate elements, install OF rules considering the next and previous connected switches
                print("*** Intermediate element of the selected path: {0}".format(i))

                # Dictionary with the info of the link between the i switch and the previous switch
                data_info_in = self.graph.get_edge_data(i, selected_path[selected_path.index(i) - 1])
                # Dictionary with the info of the link between the i switch and the next switch
                data_info_out = self.graph.get_edge_data(i, selected_path[selected_path.index(i) + 1])
                in_port = data_info_in.get('port_dpid_' + str(i))
                out_port = data_info_out.get('port_dpid_' + str(i))

                # Rule to allow traffic in the opposite direction
                print("** First rule: steer traffic in switch {0} from in_port {1} through out_port {2}".
                      format(i, in_port, out_port))
                self.logger.info("* Installing rule in the dpid %s", i)
                match = ofproto_parser.OFPMatch(in_port=in_port)
                actions = [ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 125, match, actions, selected_cookie)

                # Rule to allow traffic in the opposite direction
                print("** Second rule: other direction traffic in switch {0} with in_port {1} through out_port {2}".
                      format(i, out_port, in_port))
                self.logger.info("* Installing rule in the dpid %s", i)
                match = ofproto_parser.OFPMatch(in_port=out_port)
                actions = [ofproto_parser.OFPActionOutput(in_port)]
                self.add_flow(datapath, 125, match, actions, selected_cookie)

        # Increase the weights to avoid repeat the same path for the second flow
        self.increase_path_weight(selected_path)
        self.counter += 1

    # Function for increasing all the edges of a path
    def increase_path_weight(self, path):
        if self.counter == 0:
            print("-- Increasing weight of the path {0}".format(path))
            for i in path:
                if path.index(i) != len(path) - 1:
                    data_info = self.graph.get_edge_data(i, path[path.index(i) + 1])
                    weight_info = data_info.get("weight")
                    print("The weight of the edge is: {0}".format(weight_info))
                    print("Increasing the weight...")
                    self.graph[i][path[path.index(i) + 1]]['weight'] += 10
                    data_info = self.graph.get_edge_data(i, path[path.index(i) + 1])
                    weight_info = data_info.get("weight")
                    print("The weight of the edge is: {0}".format(weight_info))

    # This function deletes the OF rules installed in the switches with a specific cookie
    def delete_path(self, cookie):
        print("Deleting path with cookie {0}".format(cookie))
        # Look for the element of the list with the cookie argument
        if len(self.paths) != 0:
            print(self.paths)
            for item in self.paths:
                print(item)

                if item["cookie"] == cookie:
                    # Go switch by switch and delete the flows associated to a cookie
                    path_to_delete = item["path"]
                    for i in path_to_delete:
                        print("Deleting OF rules of switch with dpid {0}".format(i))
                        datapath = self.graph.nodes[i]["datapath"]
                        self.delete_flow(datapath, cookie)

                    self.paths.remove(item)
                    print(self.paths)
                else:
                    print("No cookie {0} founded".format(cookie))
        else:
            print("There is no path stored yet")

    # Function for getting the links from the controller and stored in the graph if not present
    def update_topology_links(self):
        self.logger.info("-- Updating topology links...")
        links_list = get_link(self.topology_api_app, None)
        # Obtaining the links between switches
        graph_links = [(format(link.src.dpid, "x").zfill(16), format(link.dst.dpid, "x").zfill(16),
                        {'port_dpid_' + str(format(link.src.dpid, "x").zfill(16)): link.src.port_no,
                         'port_dpid_' + str(format(link.dst.dpid, "x").zfill(16)): link.dst.port_no,
                         'weight': 1})
                       for link in links_list]

        if len(list(self.graph.edges)) == 0:
            self.graph.add_edges_from(graph_links)
        else:
            new_edges_list =[]
            stored_graph_edges = list(self.graph.edges)

            # If there are edges already stored, only add the new ones
            for item in graph_links:
                tuple_item = (item[0],item[1])
                inverse_tuple_item = (item[1],item[0])
                tuple_exist = False
                for i in stored_graph_edges:
                    if tuple_item == i or inverse_tuple_item == i:
                        tuple_exist = True
                        break
                if not tuple_exist:
                    new_edges_list.append(item)

            # Adding new edges to the graph
            if len(new_edges_list) > 0:
                self.logger.info("- Adding new edges to the graph: {0}".format(new_edges_list))
                #print(new_edges_list)
                self.graph.add_edges_from(new_edges_list)

            # Check if the funciton was called because a downed link (erase from the graph not existant links)
            self.logger.info("- Verifying downed links..")
            len_stored_graph_edges = len(stored_graph_edges)
            len_graph_links = len(graph_links)
            self.logger.info("- Length of requested links list: {0}".format(len_graph_links))
            self.logger.info("- Length of stored links list: {0}".format(len_stored_graph_edges))

            for item_stored in stored_graph_edges:
                tuple_stored_item = (item_stored[0],item_stored[1])
                inverse_tuple_stored_item = (item_stored[1],item_stored[0])
                tuple_founded = False
                for i in graph_links:
                    tuple_graph_link = (i[0],i[1])
                    if tuple_stored_item == tuple_graph_link or inverse_tuple_stored_item == tuple_graph_link:
                        # self.logger.info("- Item founded, breaking the loop...")
                        tuple_founded = True
                        break
                if not tuple_founded:
                    self.logger.info("- Item not found, so it must be deleted: {0}".format(item_stored))
                    self.graph.remove_edge(item_stored[0],item_stored[1])

            self.logger.info("-- Resulting edges stored in the graph after updating the edges of the topology: {}".format(list(self.graph.edges(data=True))))

    # Function for updating the topology information stored in the Graph property
    def update_topology(self, switch_list, links_list):
        self.logger.info("-- Recalculating topology...")

        # Obtaining the switches of the topology
        graph_nodes_switches = []
        switches = [switch.dp.id for switch in switch_list]
        print('Printing the dpid in hex format: ')
        for i_switch in switches:
            graph_nodes_switches.append((format(i_switch, "x").zfill(16), {"type": "switch"}))
            # graph_nodes_switches.append((i_switch, {"type": "switch"}))
            # print(format(i_switch, "x").zfill(16))
        print('Switches obtained by controller:')
        print(graph_nodes_switches)

        # Obtaining the links between switches
        # graph_links = [(link.src.dpid, link.dst.dpid, {'port_dpid_' + str(link.src.dpid): link.src.port_no,
        #                                               'port_dpid_' + str(link.dst.dpid): link.dst.port_no})
        #               for link in links_list]
        graph_links = [(format(link.src.dpid, "x").zfill(16), format(link.dst.dpid, "x").zfill(16),
                        {'port_dpid_' + str(format(link.src.dpid, "x").zfill(16)): link.src.port_no,
                         'port_dpid_' + str(format(link.dst.dpid, "x").zfill(16)): link.dst.port_no,
                         'weight': 1})
                       for link in links_list]

        print('Links obtained by controller:')
        print(graph_links)

        if len(list(self.graph.nodes)) == 0:
            print('Empty graph. Adding new nodes and links...')
            self.graph.add_nodes_from(graph_nodes_switches)
            self.graph.add_edges_from(graph_links)
        else:
            print('Non-Empty graph. Updating nodes and links...')
            new_graph = nx.Graph()
            new_graph.add_nodes_from(graph_nodes_switches)
            new_graph.add_edges_from(graph_links)
            self.graph = new_graph
            print('Nodes and links of supporting graph')
            print(list(new_graph.nodes))
            print(list(new_graph.edges))
            print("List of nodes and links stored in the Graph:")
            print(list(self.graph.nodes(data=True)))
            print(list(self.graph.edges))

        # Save Graph into a gml file to check updates
        print('-----------------------------------')
        nx.write_gml(self.graph, "topology-graph.gml")
        print("List of nodes stored in the Graph:")
        print(list(self.graph.nodes(data=True)))
        print("List of links stored in the Graph:")
        print(list(self.graph.edges))
        print('-----------------------------------')

    # Function to find the port of the switches connected to the infrastructure
    # TODO: define properly the utility of this function to develop it
    def find_ports_to_hosts(self):
        # Getting the host list
        print('####################### Obtaining Hosts Info #########################')
        host_list = get_host(self.topology_api_app, None)
        hosts = [host.to_dict() for host in host_list]
        print('Number of hosts detected: {0}'.format(str(len(hosts))))
        counter = 0
        # Print all elements of hosts
        for i in hosts:
            print('------- Host number: {} ------------'.format(counter))
            counter = counter + 1
            if type(i) is dict:
                for key, value in i.items():
                    print("Key: {0}; Value: {1}".format(key, value))
            print('------------------------------------')
        print('######################################################################')

    # Function for handling switch features negotiation event, storing the switches in nodes of a graph
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # dpid = format(datapath.id, "d").zfill(16)
        dpid = format(datapath.id, "x").zfill(16)
        self.logger.info("+ Handling switch %s features event.", dpid)

        # Storing the switch and its features in a graph node
        print("+++ Storing the node in the graph from the switch_features_handler event")
        if not self.graph.has_node(dpid):
            self.graph.add_node(dpid, type="switch", datapath=datapath)
            # self.graph.add_node(dpid, type="switch", of_proto=ofproto, of_proto_parser=parser, datapath=datapath)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    # Function for handling Packet-In events
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        of_proto = datapath.ofproto
        of_parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Get info about packets
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Ignore IPv6 packets
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        if pkt_ipv6:
            return

        dst = eth.dst  # Destination MAC address (string)
        src = eth.src  # Source MAC address (string)

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("Packet-in into switch %s in port: %s (src: %s; dst: %s)", dpid, in_port, src, dst)
        self.logger.info("Discarding the incomming packets...")

        ## The next lines are commented to avoid simple switch controller operations
        # learn a mac address to avoid FLOOD next time.
        ##self.mac_to_port[dpid][src] = in_port

        ##if dst in self.mac_to_port[dpid]:
        ##    out_port = self.mac_to_port[dpid][dst]
        ##else:
        ##    out_port = of_proto.OFPP_FLOOD

        ##actions = [of_parser.OFPActionOutput(out_port)]

        ### install a flow to avoid packet_in next time
        ##if out_port != of_proto.OFPP_FLOOD:
        ##    match = of_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        ##    # verify if we have a valid buffer_id, if yes avoid to send both
        ##    # flow_mod & packet_out
        ##    if msg.buffer_id != of_proto.OFP_NO_BUFFER:
        ##        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        ##        return
        ##    else:
        ##        self.add_flow(datapath, 1, match, actions)
        ##data = None
        ##if msg.buffer_id == of_proto.OFP_NO_BUFFER:
        ##    data = msg.data

        ##    out = of_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        ##                                 in_port=in_port, actions=actions, data=data)
        ##    datapath.send_msg(out)

    # Function for handling switch enter event
    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        self.logger.info("+ Handling switch enter event.")
        self.update_topology_links()
        #self.update_topology(get_switch(self.topology_api_app, None), get_link(self.topology_api_app, None))

    # TODO: Manage the situation of a link falling down (calculate new paths, install new rules, etc,)
    # Function for handling switch ports status modification events
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = format(datapath.id, "d").zfill(16)
        reason = msg.reason
        port_no = msg.desc.port_no

        # Logging about switch and its port status modification
        self.logger.info("Port status modified in switch id: %s ", dpid)
        of_proto = msg.datapath.ofproto
        if reason == of_proto.OFPPR_ADD:
            self.logger.debug("-- Port added %s", port_no)
        elif reason == of_proto.OFPPR_DELETE:
            self.logger.debug("-- Port deleted %s", port_no)
        elif reason == of_proto.OFPPR_MODIFY:
            self.logger.debug("-- Port modified %s", port_no)
            #TODO: Update the topology, check affected paths, erase bad OF rules, recalculate them
            self.update_topology_links()
            print("Paths stored before the link is down: {0}".format(self.paths))
            for item in self.paths:
                print("+++ Checking the feasibility of path: {0}".format(item))
                if self.check_feasible_path(item):
                    print('This path is still feasible, so it is not needed to be modified')
                else:
                    # Modify path
                    print('This path is not feasible, not anymore')
                    src_node = item.get('src')
                    dst_node = item.get('dst')
                    old_path = item.get('path')
                    cookie = item.get('cookie')
                    shortest_simple_path = self.calculate_paths(src_node, dst_node)[0]
                    print("Old stored path: {0}".format(old_path))
                    print("New path to store: {0}".format(shortest_simple_path))
                    print("Deleting old path...")
                    self.delete_path(cookie)
                    print('State of the stored path list: {0}'.format(self.paths))
                    self.create_flowpath(shortest_simple_path, cookie)

        else:
            self.logger.debug("Illegal port state %s %s", port_no, reason)

        #self.update_topology(get_switch(self.topology_api_app, None), get_link(self.topology_api_app, None))


# Class with the API rest functionality definition
class TopologyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyController, self).__init__(req, link, data, **config)
        # This attribute allows to synchronize the controller class and the API
        self.topology_api_app = data['topology_api_app']
        # After this, we can get and set the attributes of the upper class (e.g., self.topology_api_app.paths)

    @route('topology', '/v1.0/topology/switches',
           methods=['GET'])
    def list_switches(self, req, **kwargs):
        return self._switches(req, **kwargs)

    @route('topology', '/v1.0/topology/switches/{dpid}',
           methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_switch(self, req, **kwargs):
        return self._switches(req, **kwargs)

    @route('topology', '/v1.0/topology/links',
           methods=['GET'])
    def list_links(self, req, **kwargs):
        return self._links(req, **kwargs)

    @route('topology', '/v1.0/topology/links/{dpid}',
           methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_links(self, req, **kwargs):
        return self._links(req, **kwargs)

    @route('topology', '/v1.0/topology/hosts',
           methods=['GET'])
    def list_hosts(self, req, **kwargs):
        return self._hosts(req, **kwargs)

    @route('topology', '/v1.0/topology/hosts/{dpid}',
           methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_hosts(self, req, **kwargs):
        return self._hosts(req, **kwargs)

    # API call for connecting sites
    @route('topology', '/v1.0/topology/create_flowpath',
           methods=['GET'])
    def create_flowpath(self, req, **kwargs):
        return self._create_flowpath(req, **kwargs)

    # API call for printing paths sites
    @route('topology', '/v1.0/topology/print',
           methods=['GET'])
    def get_paths(self, req, **kwargs):
        return self._paths(req, **kwargs)

    # API call for deleting paths and OF rules
    @route('topology', '/v1.0/topology/delete_path/{cookie}',
           methods=['GET'])
    def delete_path(self, req, **kwargs):
        return self._delete_path(req, **kwargs)

    def _switches(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        switches = get_switch(self.topology_api_app, dpid)
        body = json.dumps([switch.to_dict() for switch in switches])
        return Response(content_type='application/json', body=body)

    def _links(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        links = get_link(self.topology_api_app, dpid)
        body = json.dumps([link.to_dict() for link in links])
        return Response(content_type='application/json', body=body)

    def _hosts(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            print('dpid is not None when recieving api request')
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
            print(dpid)
        hosts = get_host(self.topology_api_app, dpid)
        body = json.dumps([host.to_dict() for host in hosts])
        return Response(content_type='application/json', body=body)

    """
    From here on, all the code is related to the functionality extension for the paper
    """

    def _create_flowpath(self, req, **kwargs):
        # print('Reading API call parameters...')
        # print(kwargs)

        # Info that should be passed by the MANO entity, or being discover by an application of the controller
        switch_node_a = format(1, "x").zfill(16)
        switch_node_c = format(3, "x").zfill(16)
        metric = "weight"

        # Get all the available simple paths (this gets a list of lists)
        list_available_paths = self.topology_api_app.calculate_paths(switch_node_a, switch_node_c, metric)
        self.topology_api_app.create_flowpath(list_available_paths)

        #self.topology_api_app.increase_path_weight(list_available_paths[0])
        #self.topology_api_app.increase_path_weight(list_available_paths[len(list_available_paths) - 1])

        response = 'Received Request! Processing inter-site connection between sites...' + "<br>"
        return Response(content_type='text/html', body=response)

    def _paths(self, req, **kwargs):
        #graph_nodes = list(self.topology_api_app.graph.nodes(data="type"))
        graph_nodes = list(self.topology_api_app.graph.nodes(data=True))
        # update edges
        print("----- Showing the stored paths ---------")
        print(self.topology_api_app.paths)
        self.topology_api_app.update_topology_links()
        graph_edges = self.topology_api_app.graph.edges.data()
        response = "<b>+ Graph Nodes:</b> " + str(graph_nodes) + "<br>" + "<b>+ Graph Edges:</b> " + str(graph_edges)
        print(response)
        return Response(content_type='text/html', body=response)

    def _delete_path(self, req, **kwargs):
        print('Reading API call parameters...')
        print(kwargs)
        requested_cookie = kwargs.get("cookie")
        self.topology_api_app.delete_path(int(requested_cookie))
        response = "Received Request! Deleting path with cookie " + requested_cookie + " ..." + "<br>"
        return Response(content_type='text/html', body=response)
