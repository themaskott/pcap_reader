
# Compilation
```
cd src/
javac *.java -d ../bin
```
Java version : 17


# Execution
```
cd bin/
java PcapReader -f ../pcap/file.pcap
```

ou

```
java -jar PcapReader.jar -f pcap/file.pcap
```


# Utilisation
```
java PcapReader -f file.pcap
	-h : affiche cette aide
	-f : fichier pcap a analyser
	-v : mode verbose, affiche plus d informations sur les paquets
	-x : contenu, affiche les paquets captures en hexa
```


# Fonctionnement

Ouverture du fichier pcap, traitement des en-têtes du fichier pcap :
- recuperation des infos sur la capture
- test du magic number pcap pour discriminer l'encodage big/little endian des entêtes de capture

Itération sur les couples Packet Header / Packet Data

    --> Traitement des en-têtes du paquet ajouté par la capture
    --> Traitement des datas raw capturées = Trame de couche 2
    --> Deacpsule les protocoles
    --> Affiche au fur et à mesure les informations contenues dans les paquets

A la fin du traitement du fichier :

	--> Si des paquets IP fragmentés ont été détectés, propose de les re-assembler
	--> Propose d'extraire un flux TCP lié à un paquet TCP particulier


*Remarques :*

Le traitement de la capture est linéaire, chaque paquet capturé est extrait, traité et affiché mais n'est pas conservé en mémoire.

Ce fonctionnement n'est pas optimum pour une utilisation interactive (ex : afficher un paquet particulier, fragmentation IP ou followTC).

Le but principal est l'affichage des informations retenues, certaines classes n'instancient pas toutes les informations extraites comme attributs de l'objet correspondant, mais les mettent en forme pour l'affichage.


# Affichage

Par défaut, sont affichés les informations estimées importantes.
Notament :
- Celles liées à l'expéditeur et au destinataire (adresses, ports - Ethernet, IP, TCP, UDP)
- Celles liées au type de requête / de réponse (ARP, ICMP, DNS, flag TCP)
- Les entêtes (FTP, HTTP)

Davantage d'informations peuvent être affichées a l'aide du mode verbose.


# Fichiers

| Nom | But|
|------|-----|
| PcapReader.java | Classe principale, parcours et traitement du fichier |
| Fonctions.java | Fonctions utilisées par plusieurs classes, manipulation de tableaux d'octets, affichages |
| PcapGlobalHeaders.java | Traitement des entêtes du fichier pcap (notament le magic number -> big ou little endian) |
| PaquetHeaders.java | Traitement des entêtes placées par la capture avant chaque paquet capturé |
| Paquet[xxx].java | Traitement d'un paquet de type [xxx]
| FragmentationIP.java | Reconstitution de paquets fragmentés |
| FollowTCP.java | Extraction et suivi d'un flux TCP |


# Améliorations

- Prise en compte d'autres formats de fichiers de capture (par exemple .pcapng)
- Prise en compte de medium différents d'ethernet ( champ network du header de fichier pcap, cf http://www.tcpdump.org/linktypes.html )
- FollowTCP Stream : la récupération des paquets d'un même flux n'est pas parfaite, l'emission successive de plusieures requêtes avec le même numéro de séquence provoque plusieurs réponses qui ne sont pas toutes récupérées.
- FollowTCP Stream : la complexité de l'algorithme (quasi O(n²) ) le rend peu performant sur des captures volumineuses
- FollowTCP : la condition de fin n'est pas toujours rencontrée ( pas de paquet [FIN][ACK] en fin de capture ). Un compteur de boucle limite le nombre d'itérations mais pollue la sortie
- Affichage des datas FTP : dans la partie FTP passif mode, l'affichage produit des caractères non ASCII dans le cas de transferts de fichiers non textuels / pour le moment cet affichage est conservé car utile dans le cas de fichiers textes.
- Classe principale : renforcer la detection de protocoles (actuellement detection des ports utilisés)


# Bug possible
Pour l'affichage les [+] sont colorisés par les balises '[\033[1;32m+\033[0m]' --> attention sous Windows

# Ressources

https://github.com/markofu/pcaps/tree/master/PracticalPacketAnalysis/ppa-capture-files

https://wiki.wireshark.org/SampleCaptures

### Ethernet : 
https://fr.wikipedia.org/wiki/Ethernet

### IPv4 :
https://fr.wikipedia.org/wiki/IPv4
https://web.maths.unsw.edu.au/~lafaye/CCM/internet/protip.htm


### TCP :
https://fr.wikipedia.org/wiki/Transmission_Control_Protocol
https://web.maths.unsw.edu.au/~lafaye/CCM/internet/tcp.htm

### ARP :
http://btsirisinfo.free.fr/topologie/arp.htm

### ICMP : 
https://fr.wikipedia.org/wiki/Internet_Control_Message_Protocol

### DHCP :
https://www.frameip.com/dhcp/

options DHCP : https://www.frameip.com/rfc-2132-dhcp-options-and-bootp-vendor-extensions/

### UDP : 
https://fr.wikipedia.org/wiki/User_Datagram_Protocol

### DNS :
https://www.frameip.com/dns/
https://fr.wikipedia.org/wiki/Domain_Name_System

Champs question / reponse : https://www.frameip.com/rfc-1035-domain-names-implementation-and-specification/


Compression des labels : 
https://www.frameip.com/rfc-1035-domain-names-implementation-and-specification/
https://www.ietf.org/proceedings/43/I-D/draft-ietf-dnsind-local-compression-03.txt
http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique-2.htm

### FTP

https://www.commentcamarche.net/contents/519-le-protocole-ftp-file-transfer-protocol


# Memo

ARP Hardware type

01 – Ethernet (10Mb) [JBP] \
02 – Experimental Ethernet (3Mb) [JBP] \
03 – Amateur Radio AX.25 [PXK] \
04 – Proteon ProNET Token Ring [Doria] \
05 – Chaos [GXP] \
06 – IEEE 802 Networks [JBP] \
07 – ARCNET [JBP] \
08 – Hyperchannel [JBP] \
09 – Lanstar [TU] \
10 – Autonet Short Address [MXB1] \
11 – LocalTalk [JKR1] \
12 – LocalNet (IBM PCNet or SYTEK LocalNET) [JXM] \
13 – Ultra link [RXD2] \
14 – SMDS [GXC1] \
15 – Frame Relay [AGM]  \
16 – Asynchronous Transmission Mode (ATM) [JXB2] \
17 – HDLC [JBP] \
18 – Fibre Channel [Yakov Rekhter] \
19 – Asynchronous Transmission Mode (ATM) [RFC2225] \
20 – Serial Line [JBP]  \
21 – Asynchronous Transmission Mode (ATM) [MXB1] \
22 – MIL-STD-188-220 [Jensen] \
23 – Metricom [Stone] \
24 – IEEE 1394.1995 [Hattig] \
25 – MAPOS [Maruyama] \
26 – Twinaxial [Pitts] \
27 – EUI-64 [Fujisawa] \
28 – HIPARP [JMP] \
29 – IP and ARP over ISO 7816-3 [Guthery] \
30 – ARPSec [Etienne]  \
31 – IPsec tunnel [RFC3456] \
32 – InfiniBand (TM) [Kashyap] \
33 – TIA-102 Project 25 Common Air Interface (CAI) [Anderson] 

| EtherType | Protocole |
|-----------|-----------|
| 0x0800 | Internet Protocol version 4 (IPv4) |
| 0x0806 | Address Resolution Protocol (ARP) |
| 0x0842 | Wake-on-LAN1 |
| 0x22F3 | IETF TRILL Protocol |
| 0x6003 | DECnet Phase IV |
| 0x8035 | Reverse Address Resolution Protocol (RARP) |
| 0x809b | AppleTalk (Ethertalk) |
| 0x80F3 | AppleTalk Address Resolution Protocol (AARP) |
| 0x8100 | VLAN-tagged frame (IEEE 802.1Q) & Shortest Path Bridging IEEE 802.1aq2 |
| 0x8137 | Novell IPX (alternatif) |
| 0x8138 | Novell |
| 0x8204 | QNX Qnet |
| 0x86DD | Internet Protocol, Version 6 (IPv6) |
| 0x8808 | Ethernet flow control |
| 0x8809 | Slow Protocols (IEEE 802.3) |
| 0x8819 | CobraNet |
| 0x8847 | MPLS unicast |
| 0x8848 | MPLS multicast |
| 0x8863 | PPPoE Discovery Stage |
| 0x8864 | PPPoE Session Stage |
| 0x8870 | Jumbo Frames |
| 0x887B | HomePlug 1.0 MME |
| 0x888E | EAP over LAN (IEEE 802.1X) |
| 0x8892 | Profinet RT |
| 0x8896 | Ethersound |
| 0x889A | HyperSCSI (SCSI over Ethernet) |
| 0x88A2 | ATA over Ethernet |
| 0x88A4 | EtherCAT Protocol |
| 0x88A8 | Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq3 |
| 0x88AB | Powerlink |
| 0x88CC | Link Layer Discovery Protocol (LLDP) |
| 0x88CD | Sercos |
| 0x88E1 | HomePlug AV MME[citation nécessaire] |
| 0x88E3 | Media Redundancy Protocol (IEC62439-2) |
| 0x88E5 | MAC security (IEEE 802.1ae) |
| 0x88F7 | Precision Time Protocol (IEEE 1588) |
| 0x8902 | IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM) |
| 0x8906 | Fibre Channel over Ethernet (FCoE) |
| 0x8914 | FCoE Initialization Protocol |
| 0x8915 | RDMA over Converged Ethernet (RoCE) |
| 0x9000 | Configuration Testing Protocol (Loop)4, utilisé notamment pour les keepalives Ethernet chez Cisco5 |
| 0x9100 | Q-in-Q |
| 0xCAFE | Veritas Low Latency Transport (LLT)6 for Veritas Cluster Server |