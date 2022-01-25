import java.io.* ;

// classe PaquetEthernet
// traitement du paquet de data issu du pcap

// /!\ les octets ne sont pas inverses 


// trame ethernet
//  -------------------------------------------------------------------------------------------------------------------------------------------
// | MAC dest | MAC srce | tag 802.1Q (optionel) | Ethertype (ethernet II) ou longeur (IEEE 802.3) | LLC/CNAP (si 802.3) + payload | CRC
//  -------------------------------------------------------------------------------------------------------------------------------------------
//   6o             6o          ( 4o )                          2o                                      ( 46 - 1500 o )                 4 o                


// 0x0800 : IPv4
// 0x86DD : IPv6
// 0x0806 : ARP
// 0x8035 : RARP
// 0x809B : AppleTalk
// 0x88CD : SERCOS III
// 0x0600 : XNS
// 0x8100 : VLAN

public class PaquetEthernet {

    // data recupere en tableau de string hexa
    String[] tabEthernetData ;

    String adresseDest, adresseEmet ;
    String etherType ;
    String [] dataEthernet ;

    PaquetEthernet( DataInputStream pcapFile, int sizeData ){

        this.tabEthernetData = new String[ sizeData ] ;

        // recuperation des datas du paquet dans un tableau
        this.tabEthernetData = Fonctions.readOctetsHex( pcapFile, sizeData ) ;
        
        // recuperation de l adresse destination
        this.adresseDest = String.join(":", Fonctions.extractArray( this.tabEthernetData, 0, 5, false ));

        // recuperation de l adresse emeteur
        this.adresseEmet = String.join(":", Fonctions.extractArray( this.tabEthernetData, 6, 11, false ));

        // recuperation du type ethernet
        this.etherType = String.join("", Fonctions.extractArray( this.tabEthernetData, 12, 13, false)) ;

        // recuperation des donnees transportees (taille trame etherne - 2 adresses MAC - ethertype - CRC)
        this.dataEthernet = new String[ sizeData - 12 - 2 ] ;  // apparement le CRC n est pas conserve dans les captures par wireshark, sinon sizeData -12 -2 -4
        this.dataEthernet = Fonctions.extractArray( this.tabEthernetData, 14, sizeData - 1, false ) ;  // idem, sinon sizeData -4
    }   

    // affichPaquetData
    // affiche les datas du paquet
    public void affichPaquetEthernet( boolean verbose ){

        System.out.println("[\033[1;32m+\033[0m] ETHERNET") ;
        System.out.println( "Adresse Destination : " + this.adresseDest ) ;
        System.out.println( "Adresse Emetrice : " + this.adresseEmet ) ;
        System.out.println( "Type Ethernet : 0x" + this.etherType ) ;


    }

}
