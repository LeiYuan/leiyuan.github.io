# MDP MPLS L3VPN Design

## 1. Functional Requirements

### Control Plane Requirements

- Supports configuring loopback interface. Routing protocols like LDP and BGP will use loopback IP as the source IP of their control messages
- Supports configuring GRE tunnel interfaces. This is to support routing protocols and MPLS traffic over GRE tunnel, which allows traffic to be traversed over shared network infrastructure 
- supports OSPF as IGP protocol for advertising its loopback IP and learning other routers' loopback IPs
- supports OSPF over GRE
- supports LDP over GRE for exchanging transport labels with P router
- supports configuring VRFs to support VPN routes across multiple routing tables
- supports MP-iBGP over GRE for exchanging VPN label with peer PE router

Below diagram shows typical network topology for MPLS L3VPN.

 ![](D:\Project\5G\MDP\Design\VRF & MPLS VPN\MD\images\l3vpn_typical_topology.jpg)



MDP runs as a PE router sitting at the edge of the MPLS core network. It talks with P1 router through OSPF and LDP; talks with PE2 indirectly through MP-iBGP protocol. MDP shall support following use cases of CE network separation. 

- In UPF use case, subscribers are divided to different VRFs by the APNs to which they get attached 
- In virtual router use case, multiple network interfaces can be configured on MDP and interfaces can be bind to different VRFs
- In SeGW use case, IPSec tunnels can be used for network separation

### Data Plane Requirements 

- Supports MPLS encapsulation and decapsulation
- Supports add IP and MPLS routes on VRF routing table
- MPLS packets sent from PE1/MDP to P1 router have both outer label(transport label) and inner label(VPN label)
- Transport label in outgoing packet is learned from LDP protocol
- VPN label is learned from MP-iBGP whose messages are exchanged indirectly b/w PE1/MDP and PE2 
- MPLS packets sent from P1 to PE1/MDP only have VPN label if PHP(Penultimate hop popping) is enabled
- Supports identifying target VRF by the VPN label of incoming MPLS packet 

## 2. Case study - DTAG Campus Project

### DTAG Campus Overview

The network topology of DTAG campus solution is depicted as below diagram.

![](D:\Project\5G\MDP\Design\VRF & MPLS VPN\MD\images\DTAG_Campus.png)



In this solution, RAN nodes are located at campus sites. Mavenir packet core is deployed as shared infrastructure for all campus locations. The traffic generated on the mobile network is routed back to customer site via IPSec tunnel through public internet. To meet the routing requirements, ECON GW is introduced.  The solution can be seen as a standard MPLS layer 3 VPN architecture. The PGW and vSRX are acting as PE routers. vMX acts as both a P router and a BGP router reflector. Due to the traffic from PGW needs to go through DTAG IP backbone to reach vMX,  MPLS over GRE tunnel is adopted to avoid customer specific configurations on the transport path between Core and ECON GW. 

Below diagram shows the logical architecture after mapping DTAG campus solution to MPLS layer 3 VPN topology.

![](D:\Project\5G\MDP\Design\VRF & MPLS VPN\MD\images\Campus_logic.png)



### Reference Network for POC

FRRouting (FRR) is a free and open source Internet routing protocol suite for Linux and Unix platforms. It implements BGP, OSPF, RIP, IS-IS, PIM, LDP, BFD, Babel, PBR, OpenFabric and VRRP, with alpha support for EIGRP and NHRP. It is a production ready dynamic routing protocol suite and has been widely used by many projects and companies. 

We plan to leverage FRR's OSPF, BGP and LDP features to implement control plane of routing functions of DTAG campus solution. This requires us to integrate FRR in MDP to provide the dynamic routing protocol support to applications. Thus, we set up a reference network to prove FRR have all the required functionalities of campus project. In this section we'll describe configurations of this setup in detail.

The setup consists of 7 docker containers running on a ubuntu 18.04.6 host server. All the docker containers are based on ubuntu 20.4 official docker image and have FRR 8.0 installed on it. 

|      Software      |      Version       |
| :----------------: | :----------------: |
|      Host OS       |   ubuntu 18.04.6   |
|    Host Kernel     | 4.15.0-166-generic |
| OS on Docker image |    ubuntu 20.4     |
|        FRR         |     8.0 stable     |

Below diagram depicts the topology of the reference network. Although only IPv4 is discussed in this document, IPv6 also needs to be supported in this feature.     

![](D:\Project\5G\MDP\Design\VRF & MPLS VPN\MD\images\frr_simu_setup.png)



Note: OSPF, LDP and BGP protocol daemons are running on PE1, P and PE2 routers. The target of the setup is:

- Ping from CE1_A to CE1_B should work
- Ping from CE2_A to CE2_B should work

In this design, we plan to add dynamic routing and MPLS features to MDP to enable applications running as a PE router. So, we'll focus on PE functionalities of a MPLS layer3 VPN in this document.  

#### Configure Loopback Interface

loopback interfaces are configured on PE1, P and PE2 routes. Loopback interface is a virtual interface which doesn't rely on state of any physical interfaces. The loopback interface is stable because once you enable it, it will remain up until you shut it down. The IP address configured on loopback interface is often used by routing protocols like LDP and BGP. In this setup, we are using loopback for the same.

```
PE1/MDP loopback interface config:
ip link add dummy0 type dummy
ip link set dummy0 up
ip addr add 2.2.2.2/32 dev dummy0
```

#### Configure GRE interface  

 The GRE interface is a virtual interface which behave as virtual point-to-point link that have two endpoints identified by the tunnel source(local)  and tunnel destination(remote) address. When a packet is forwarded through a GRE tunnel interface, two new headers, i.e. outer IP header and GRE header, are added to the front of the packet. This process is call GRE encapsulation. The encapsulated packet will be then routed to its destination through physical interface; Once the GRE packet reaches the tunnel destination endpoint, the new IP header and the GRE header are removed from the packet and the original IP header is used to forward the packet to the final destination.

In this setup, a GRE tunnel interface is created on both PE1 router and P router. OSPF, LDP and BGP protocol messages are forwarded over it.

```
PE1/MDP GRE interface config:
ip tunnel add gre1 mode gre remote 192.168.23.3 local 192.168.23.2 ttl 255
ip link set gre1 up
ip addr add 10.10.10.2/24 dev gre1
```

#### Configure OSPF Protocol

In this setup, OSPF is running at PE and P routers to advertise their loopback IPs. PE1 and P are learning the other's GRE interface IP through OSPF as well. Here is the OSPF FRR config on PE1.

```
interface gre1
 ip ospf network point-to-point
 
router ospf
 ospf router-id 2.2.2.2
 redistribute connected
 redistribute static
 network 2.2.2.2/32 area 0
 network 10.10.10.0/24 area 0
 exit
```

PE1 would learn below IP routes through OSPF.

```
3.3.3.3 via 10.10.10.3 dev gre1 proto ospf metric 20 
5.5.5.5 via 10.10.10.3 dev gre1 proto ospf metric 20 
10.10.10.0/24 dev gre1 proto kernel scope link src 10.10.10.2 
```

#### Configure LDP Protocol

Before configuring LDP on FRR, we need to load MPLS kernel module on host server.

```
modprobe mpls_router
modprobe mpls_iptunnel
modprobe dummy // note for loopback
```

Secondly, we apply following kernel setting in PE container to enable kernel MPLS forwarding.

```
net.mpls.conf.eth2.input=1
net.mpls.conf.gre1.input=1
net.mpls.platform_labels=100000
```

LDP FRR config on PE1 is as following:

```
mpls ldp
 router-id 2.2.2.2
 !
 address-family ipv4
  discovery transport-address 2.2.2.2
  !
  interface gre1
  !
 exit-address-family
 !
```

PE1 would learn below routes related to MPLS through LDP.

```
ip route show
 5.5.5.5  encap mpls  16 via 10.10.10.3 dev gre1 proto ospf metric 20
 
ip -f mpls route show
 16 via inet 10.10.10.3 dev gre1 proto 193 
 17 as to 16 via inet 10.10.10.3 dev gre1 proto 193 
 18 via inet 10.10.10.3 dev gre1 proto 193 
```

#### Configure MP-BGP Protocol

Here are commands for configuring two VRFs in PE1 kernel.

```
ip link add custvrf1 type vrf table 100
ip link set custvrf1 up
ip route add vrf custvrf1 unreachable default metric 4278198272
ip link set eth1 vrf custvrf1
ip link set eth1 up 
ip addr add 172.19.0.2/24 dev eth1

ip link add custvrf2 type vrf table 200
ip link set custvrf2 up
ip route add vrf custvrf2 unreachable default metric 4278198272
ip link set eth3 vrf custvrf1
ip link set eth3 up 
ip addr add 172.19.0.2/24 dev eth3
```

MP-BGP FRR config on PE1 is as following:

```
router bgp 65000
 no bgp default ipv4-unicast
 neighbor 3.3.3.3 remote-as 65000
 neighbor 3.3.3.3 update-source dummy0
 !
 address-family ipv4 vpn
  neighbor 3.3.3.3 activate
 exit-address-family
!
router bgp 65000 vrf custvrf1
 !
 address-family ipv4 unicast
  redistribute connected
  redistribute static
  label vpn export auto
  rd vpn export 65000:100
  rt vpn both 65000:100
  export vpn
  import vpn
 exit-address-family
 !

router bgp 65000 vrf custvrf2
 !
 address-family ipv4 unicast
  redistribute connected
  redistribute static
  label vpn export auto
  rd vpn export 65000:200
  rt vpn both 65000:200
  export vpn
  import vpn
 exit-address-family
```

Below routes are learned through MP-BGP protocol.

```
ip -f mpls r
 80 dev custvrf1 proto bgp
 81 dev custvrf2 proto bgp
 
ip route show table 100
 172.19.2.0/24  encap mpls  16/80 via 10.10.10.3 dev gre1 proto bgp metric 20
 
ip route show table 200
 172.19.2.0/24  encap mpls  16/80 via 10.10.10.3 dev gre1 proto bgp metric 20
```

#### Data Plane Capture

Following 2 diagrams show how ping/ICMP Echo Request and Response packets between CE1_A and CE1_B (CE2_A and CE2_B follow the same) are handled  at each router.

##### ICMP Echo Request:

![](D:\Project\5G\MDP\Design\VRF & MPLS VPN\MD\images\ping_request.png)

##### ICMP Echo Response:

![](D:\Project\5G\MDP\Design\VRF & MPLS VPN\MD\images\ping_reply.png)

## 3. Design

### MDP Overall Architecture

To maximum packet processing performance and lower its latency on Fast Path, we adopted a control plane and data plane separated architecture. CPU cores on the system(bare metal, VM or Container) are divided and dispatched to control plane applications and Fast Path respectively.  Below diagram depicts overall MDP architecture after adding dynamic routing protocol suite(drpd) into it by FRR integration.

![](D:\Project\5G\MDP\Design\VRF & MPLS VPN\MD\images\mdp_arch_w_frr.png)

As we can see, DPRD/FRR is running on MDP control plane. It starts all the configured routing protocol daemons and handle all routing messages. The best routes selected from active routes learned from various routing daemons are installed into kernel FIB using netlink. DPRD also provide GRPC APIs for configuration itself and telemetry purpose.  

The design of FRR integration with MDP will be addressed in next release, thus it is out of the scope of current doc. 

### Synchronization of Routing States

In FRR architecture, routing protocols such as BGP, OSPF and LDP are implemented in processes or daemons such as bgpd, ripd, ospfd, ldpd, etc. Another daemon called zebra, acts as an intermediary between the kernel’s forwarding plane and the routing protocol daemons.   

The zebra's purpose is to maintain a backup of packet forwarding state, such as the network interfaces and the table of currently active routes. The zebra process collects routing information from the routing protocol processes and stores these in its own Routing Information Base (RIB) whereas, static routes are also configured. The zebra process then is responsible for selecting the best route from all those available for a destination and updating the kernel FIB . Additionally, information about the current best routes may be distributed to the protocol daemons. The zebra process maintains the routing daemons updated if any change occurs in the network interface state.

Since FRR talks with kernel FIB instead of VPP based data plane, to simply FRR integration, existing VPP SYNC plugin will be enhanced to learn MPLS related routes through kernel netlink notifications. See below diagram.

 ![](D:\Project\5G\MDP\Design\VRF & MPLS VPN\MD\images\syncd.png)  

SYNC plugin is mainly responsible for listening on netlink socket and acting as a netlink to VPP mapper. It will make sure the kernel FIB and LFIB are in sync with VPP FIB and LFIB. Since SYNC plugin has already supported synchronization of non-MPLS routes for both IPv4 and IPv6, only MPLS related route learning through LDP and MP-BGP protocols are covered in this section. Below are sample use cases. 

```
## These couple of MPLS routes represent MPLS label to VRF mapping.  
ip -f mpls r
 80 dev custvrf1 proto bgp
 81 dev custvrf2 proto bgp

==>VPP: 
mpls local-label 80 via ip4-lookup-in-table 100
mpls local-label 81 via ip4-lookup-in-table 200
```

```
ip route show
 5.5.5.5  encap mpls  16 via 10.10.10.3 dev gre1 proto ospf metric 20
 
ip route show table 100
 172.19.2.0/24  encap mpls  16/80 via 10.10.10.3 dev gre1 proto bgp metric 20

==>VPP:
ip route add 5.5.5.5/32 via 10.10.10.3 gre1 out-labels 16
ip route add table 100 172.19.2.0/24 via 5.5.5.5 next-hop-table 0 out-label 80
```

```
ip -f mpls route show
 16 via inet 10.10.10.3 dev gre1 proto 193 
 17 as to 16 via inet 10.10.10.3 dev gre1 proto 193 
 18 via inet 10.10.10.3 dev gre1 proto 193 

==>VPP:
mpls local-label 16 via 10.10.10.3 next-hop-table 0
mpls local-label 17 via 10.10.10.3 gre1 out-labels 16
mpls local-label 18 via 10.10.10.3 next-hop-table 0
```

with SYNC plugin, FRR can still talk to kernel without any change. It will ease the integration effort and improve stability of the overall solution.

### Create Virtual Interfaces on MDP

upAgent shall provide configuration APIs to application for creating loopback and GRE tunnel interfaces on MDP.

#### Lookback Interface

Loopback interface is independent of the state of any physical interface; thus, a loopback interface can provide a stable interface on which you can assign an IP address. This address can be configured as transport address of LDP and BGP IP. Upon receiving the API, MDP shall create loopback interface on both kernel and VPP. Any packet received from loopback on VPP needs to be transferred to kernel. 

#### GRE Tunnel Interface

GRE tunnel allows UPF, and P router communicate with each other over a different transport network. Application needs to provide below info to create a GRE tunnel interface:

- Tunnel Remote IP
- Tunnel Local IP

 GRE tunnel interface acts as a real network interface on MDP. IP address can be configured on it.

```
"GRE_INTERFACE": {
    "gre1":{
        "local_ip":"192.168.23.2",
        "remote_ip":"192.168.23.2",
        "ip_address":"10.10.10.2/24"
    }
}
```

Below diagram shows how the OSPF/LDP/BGP over GRE works on MDP. 

![](D:\Project\5G\MDP\Design\VRF & MPLS VPN\MD\images\RP over GRE.png)

- Upon receiving the API, MDP shall create a GRE interface on VPP; In the mean time, create a TUN interface in Linux kernel with same name as its counterpart.  
- The outgoing routing protocol message is handled with below logic
  1. Routing daemon sends a message to its peer, the message is passed to Linux kernel as an IP packet. After route lookup on destIP, the packet is transmitted out through GRE1 interface
  2. GRE1 is a TUN interface, VPP TAP plugin will receive the IP packet by reading data from the TUN interface
  3. TAP plugin knows the counterpart of the GRE1 TUN interface is GRE1 interface in VPP, so, it transmits packet out by calling GRE1 output function
  4. GRE1 does GRE encapsulation against the IP packet 
  5. The encapsulated GRE packet is sent out over its underlying physical interface which is fpeth0

- The incoming routing protocol message is handled with below logic
  1. A GRE packet is received from physical interface fpeth0
  2. The packet is passed to GRE1 interface, where a GRE decapsulation is done
  3. Since the destination IP of inner packet is local IP, the packet is passed to TAP plugin 
  4. TAP plugin knows the counterpart of the VPP GRE1 interface is GRE1 TUN interface on Linux kernel. So, it sends the packet to Linux kernel by writing data to TUN interface
  5. Finally the GRE inner packet is passed to the routing daemon who is listening on specific L4 port

### Create VRF on MDP

