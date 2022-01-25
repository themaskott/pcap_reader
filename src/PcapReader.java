// ESIEA - MS SIS
// RZO - Projet
// 
// 06.10.2021
// @Maskott

// format du fichier pcap
//  ----------------------------------------------------------------------------------------------------------------
// | Global Header | Packet Header | Packet Data | Packet Header | Packet Data | Packet Header | Packet Data | ...  |
//  ----------------------------------------------------------------------------------------------------------------

import java.util.* ;
import java.io.* ;


public class PcapReader {
    public static void main( String[] args ) throws Exception {

        // nom de fichier pcap
        String pcapFileName = "" ;
        boolean verbose = false ;
        boolean showContent = false ;
       
        // compteur des paquets pour affichage
        int numPaquet = 1 ;

        // flux fichier pcap
        DataInputStream pcapFile = null ;

        // Objets headers
        PcapGlobalHeaders pcapGlobalHeaders ;
        PaquetHeaders paquetHeaders ;
        
        // Objets data ( i e data capture - couche 2)
        PaquetEthernet paquetEthernet ;
        int sizepaquetEthernet = 0 ;

        PaquetARP paquetARP ;
        
        // Objets encapsules ( couche 3 )
        PaquetIPv4 paquetIPv4 ;
        PaquetICMP paquetICMP ;
        
        // Objets encapsules ( couch 4 )
        PaquetTCP paquetTCP ;
        PaquetUDP paquetUDP ;
        PaquetDHCP paquetDHCP ;
        PaquetDNS paquetDNS ;
        PaquetDNSoverTCP paquetDNSoverTCP ;

        PaquetHTTP paquetHTTP ;
        PaquetFTP paquetFTP = new PaquetFTP() ;
        int ftpServerPort = 0 ;

        // liste pour la fragmentation IP
        //au fur et a mesure de la lecture du pcap les paquets IPv4 sont ajoutes a la liste
        FragmentationIP paquetIPv4List = new FragmentationIP() ;
        int nbPaquetIPfragment = 0 ;
        String identifPaquetFragment = "" ;

        // liste pour le stream TCP
        FollowTCP followTCP = new FollowTCP() ;
        int nbPaquetTCP = 0 ;

        // gestion des arguments de la commande de lancement
        if ( args.length == 0 ){
            Fonctions.showMenu() ;
        }
        else {
            
            List<String> argsList = Arrays.asList( args ) ;
            
            if ( argsList.contains( "-f" )){
                pcapFileName = argsList.get( argsList.indexOf( "-f") + 1 ) ;   
            }
            else if ( argsList.contains( "-h" ) ){
                Fonctions.showMenu() ;
            }
            else {
                Fonctions.showMenu() ;
            }

            if ( argsList.contains( "-v" )){
                verbose = true ;
            }
            if ( argsList.contains( "-x" )){
                showContent = true ;
            }
        }

        

        try {
            // lecture du fichier pcap
            pcapFile = new DataInputStream( new FileInputStream( pcapFileName )) ;
            System.out.println();
            System.out.println( "---------------------------------------------" ) ;
            System.out.println( "[\033[1;32m+\033[0m] Ouverture et lecture du fichier pcap" ) ;
            System.out.println( "---------------------------------------------" ) ;
            System.out.println();

            // traitement des headers du pcap
            pcapGlobalHeaders = new PcapGlobalHeaders( pcapFile ) ;
            pcapGlobalHeaders.affichPcapHeaders() ;

            while ( true ) {
                // todo : test du type de trame transporte, si ethernet envoi a la classe, sinon drop et information, / rajout wifi

                // recuperation des headers du paquet brut capture
                paquetHeaders = new PaquetHeaders( pcapFile, pcapGlobalHeaders.swapped ) ;

                // recuperation de la taille des datas a lire
                sizepaquetEthernet = paquetHeaders.paquetSize ;
                
                // recuperation des datas
                paquetEthernet = new PaquetEthernet( pcapFile, sizepaquetEthernet ) ;
                System.out.println() ;
                System.out.printf( ">>> No %d  |  ------------------------------------------------------------------ >>>\n\n", numPaquet ) ;
                // affiche les informations de capture
                paquetHeaders.affichPaquetHeaders( verbose ) ;
                // affiche les information ethernet
                paquetEthernet.affichPaquetEthernet( verbose ) ;


                // IPv4
                if ( paquetEthernet.etherType.equals( "0800" )){

                    paquetIPv4 = new PaquetIPv4( paquetEthernet.dataEthernet ) ;
                    paquetIPv4.affichePaquetIPv4( verbose ) ;

                    // ajout du paquet a la liste pour la reconstitution des fragments si necessaire
                    paquetIPv4List.ajoutPaquet( paquetIPv4 );

                    // compte le nombre de paquets fragmentes (i.e indicateur = 1)
                    if ( paquetIPv4.indicateur == 1 ){
                        nbPaquetIPfragment += 1 ;
                        identifPaquetFragment += paquetIPv4.identificationFragment + " " ;
                    }
                    
                    // TCP
                    // le protocole encapsule dans TCP est suppose en fonction du port
                    // la verification sur la taille permet de ne pas chercher a decapsuler les echange du handshake
                    if ( paquetIPv4.numProtocole == 6 ){
                        paquetTCP = new PaquetTCP( paquetIPv4.dataIPv4 ) ;
                        paquetTCP.affichPaquetTCP( verbose ) ;

                        // ajout du paquet a la liste pour suivre le flux si besoin
                        followTCP.ajoutPaquet( paquetTCP ) ;
                        // taggage du paquet
                        paquetTCP.numPaquet = numPaquet ;
                        nbPaquetTCP += 1 ;

                        // DHCP
                        if (( paquetTCP.portDest == 67 || paquetTCP.portSource == 67 ) && paquetTCP.size > paquetTCP.sizeEnTete * 4 ){
                            paquetDHCP = new PaquetDHCP( paquetTCP.dataTCP ) ;
                            paquetDHCP.affichPaquetDHCP( verbose ) ;
                        }
                        //DNS
                        else if (( paquetTCP.portDest == 53 || paquetTCP.portSource == 53 ) && paquetTCP.size > paquetTCP.sizeEnTete * 4 ){
                            paquetDNSoverTCP = new PaquetDNSoverTCP( paquetTCP.dataTCP ) ;
                            paquetDNSoverTCP.affichPaquetDNS( verbose ) ;
                        }
                        //HTTP
                        else if (( paquetTCP.portDest == 80 || paquetTCP.portSource == 80 ) && paquetTCP.size > paquetTCP.sizeEnTete * 4 ){
                            paquetHTTP = new PaquetHTTP( paquetTCP.dataTCP ) ;
                            paquetHTTP.affichPaquetHTTP( verbose ) ;
                        }
                        //FTP
                        else if (( paquetTCP.portDest == 21 || paquetTCP.portSource == 21) && paquetTCP.size > paquetTCP.sizeEnTete * 4 ){
                            paquetFTP = new PaquetFTP( paquetTCP.dataTCP ) ;

                            // si un port est prpose par le serveur lors du passage en mode passif
                            // on recupere ce port
                            if ( paquetFTP.ftpDataServerPort != 0 ){
                                ftpServerPort = paquetFTP.ftpDataServerPort ;
                            }
                            paquetFTP.affichPaquetFTP( verbose ) ;
                        }
                        // FTP mode passif
                        else if ( ftpServerPort != 0 && ( paquetTCP.portDest == ftpServerPort || paquetTCP.portSource == ftpServerPort ) && paquetTCP.size > paquetTCP.sizeEnTete * 4 ){
                            paquetFTP = new PaquetFTP( paquetTCP.dataTCP ) ;
                            paquetFTP.affichPaquetFTP( verbose ) ;
                        }
                    } 
                    // ICMP 
                    else if ( paquetIPv4.numProtocole == 1 ){
                        paquetICMP = new PaquetICMP( paquetIPv4.dataIPv4 ) ;
                        paquetICMP.affichPaquetICMP( verbose ) ;
                    }
                    // UDP
                    else if ( paquetIPv4.numProtocole == 17 ){
                        paquetUDP = new PaquetUDP( paquetIPv4.dataIPv4 ) ;
                        paquetUDP.affichPaquetUDP( verbose ) ;
                        // DHCP
                        if ( paquetUDP.portDest == 67 || paquetUDP.portSource == 67){
                            paquetDHCP = new PaquetDHCP( paquetUDP.dataUDP ) ;
                            paquetDHCP.affichPaquetDHCP( verbose ) ;
                        }
                        //DNS
                        if ( paquetUDP.portDest == 53 || paquetUDP.portSource == 53){
                            paquetDNS = new PaquetDNS( paquetUDP.dataUDP ) ;
                            paquetDNS.affichPaquetDNS( verbose ) ;
                        }
                    }                         
                }
                // ARP
                else if ( paquetEthernet.etherType.equals( "0806")){
                    paquetARP = new PaquetARP( paquetEthernet.dataEthernet ) ;
                    paquetARP.affichPaquetARP( verbose);
                }
                //IPv6
                else if ( paquetEthernet.etherType.toLowerCase().equals( "86dd")){
                    System.out.println( "[-] IPv6 -- Non encore supporte" ) ;
                }
                // affichage du contenu brut du paquet capture
                if ( showContent ){
                    Fonctions.affichDataHexa( paquetEthernet.tabEthernetData ) ;
                }
            numPaquet++ ;
            }//while
        }
        catch ( IOException ioe ) {
            System.out.println( "---------------------------------------------" ) ;
            System.out.println( "[\033[1;32m+\033[0m] Probleme d ouverture du fichier" ) ;
            System.out.println( "---------------------------------------------" ) ;
            System.err.println( ioe ) ;
            System.exit(1) ;
        }
        catch ( NumberFormatException e ) {
            System.out.println( "---------------------------------------------" ) ;
            System.out.println( "[\033[1;32m+\033[0m] Fin de lecture du fichier" ) ;
            System.out.println( "---------------------------------------------" ) ;
        }
        

        // prepare la lecture des choix utilisateurs
        Scanner sc = new Scanner(System.in) ;
        String saisie = "" ;


        System.out.println();
        System.out.println( "---------------------------------------------" ) ;
        System.out.println( "[\033[1;32m+\033[0m] Informtions sur la capture" ) ;
        System.out.println( "---------------------------------------------" ) ;
        System.out.println();


        if ( nbPaquetIPfragment > 0){
            System.out.printf("Fragmentation IP : %d paquets IPv4 sont fragmentes\n", nbPaquetIPfragment );
            System.out.println("Identification des paquets : " + identifPaquetFragment) ;
            System.out.println() ;
            System.out.print("Voulez vous reconstituer les paquets ? (o/n) ") ;

            saisie = sc.nextLine() ;

            if ( saisie.equals("o") ){
                paquetIPv4List.reconstituerTousPaquet( identifPaquetFragment );
            }

        }
        else{
            System.out.println() ;
            System.out.println("Aucun paquet IP fragmete n a ete detecte") ;
            System.out.println() ;


        }


        if ( nbPaquetTCP != 0 ){
            System.out.println();
            System.out.println( "---------------------------------------------" ) ;
            System.out.println( "[\033[1;32m+\033[0m] Suivre un flux TCP" ) ;
            System.out.println( "---------------------------------------------" ) ;
            System.out.println();
            System.out.print("Voulez vous reconstituer un flux TCP ? (o/n) ") ;

            saisie = sc.nextLine() ;
            if ( saisie.equals("o") ){
                System.out.print("Saisissez le numero d un paquet du flux : ") ;
                saisie = sc.nextLine() ;


                followTCP.chercherFlux(Integer.parseInt(saisie)) ;
                followTCP.afficherFlux() ;
            }
        }
        else{
            System.out.println() ;
            System.out.println("Aucun paquet TCP n a ete detecte") ;
            System.out.println() ;
        }

        // fermeture du scanner
        sc.close() ;



    }//main
}//class
