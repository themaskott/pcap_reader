import java.util.* ;
 


// FollowTCP
// la liste paquetTCPlist est enrichie de tous les paquets TCP parses par PcapReader
public class FollowTCP {
    
    // liste de tous les paquets TCP
    List<PaquetTCP> paquetTCPlist ;

    // liste des paquets extraits pour un flux donne
    List<PaquetTCP> fluxTCP = new ArrayList<PaquetTCP>() ;

    // liste des paquets du flux ordonnes
    List<PaquetTCP> fluxTCPordonne = new ArrayList<PaquetTCP>() ;

    // port client/server du flux a considerer
    int port1 = 0 ;
    int port2 = 0 ;

    FollowTCP(){
        this.paquetTCPlist = new ArrayList<PaquetTCP>() ;
    }

    public void ajoutPaquet( PaquetTCP paquetTCP ){
        this.paquetTCPlist.add( paquetTCP ) ;
    }



    // rechercher un flux TCP parmis tous les paquets TCP
    // le paquet cible est identifie par son numero de paquet dans la capture, saisi par l utilisateur
    public void chercherFlux( int numPaquet ){


        // recuperation des ports source et destination du paquet recherche
        for ( int i = 0 ; i < this.paquetTCPlist.size() ; i ++ ){
            if ( this.paquetTCPlist.get(i).numPaquet == numPaquet ){
                this.port1 = this.paquetTCPlist.get(i).portSource ;
                this.port2 = this.paquetTCPlist.get(i).portDest ;
            }
        }

        // recupere les paquets identifies dans le liste "flux"
        for ( int i = 0 ; i < this.paquetTCPlist.size() ; i ++ ){
            if ( ( this.paquetTCPlist.get(i).portSource == port1 || this.paquetTCPlist.get(i).portSource == port2 ) && ( this.paquetTCPlist.get(i).portDest == port1 || this.paquetTCPlist.get(i).portDest == port2 ) ){
                this.fluxTCP.add( this.paquetTCPlist.get(i) );
            }
        }


        Boolean continuer = true ;
        int numPaquetOrd = 0 ;
        int limitMax = 0 ;

        // recherche le premier paquet du flux et l inscrit en premier dans fluxTCPordonne
        // ce premier paquet a son champ numero acquittement == 0
        for ( int i  = 0 ; i < this.fluxTCP.size() ; i++ ){
            if ( this.fluxTCP.get(i).numAcquit == 0 && this.fluxTCP.get(i).flagSYN ){
                this.fluxTCPordonne.add( this.fluxTCP.get(i) ) ;
                break ;
            }
        }

        // parcours plusieurs fois fluxTCP pour rechercher le paquet suivant et l ajouter a fluxTCPordonne
        // ce paquet a soit un numero d acquittemnent egal au numero de sequence du precedent incremente de la taille des donnees recues + 1
        // soit un numero de sequence egal au numero d acquittement precedent
        // la condition sur limitMax evite les boucles infinies dans le cas de capture mal terminees ( sans [FIN][ACK])
        while( continuer && limitMax < this.fluxTCP.size() ){


            for ( int i = 0 ; i < this.fluxTCP.size() ; i++ ){
                if ( this.fluxTCP.get(i).numAcquit == this.fluxTCPordonne.get( numPaquetOrd ).numSequence + this.fluxTCPordonne.get( numPaquetOrd ).size - this.fluxTCPordonne.get( numPaquetOrd ).sizeEnTete * 4 + 1 ){
                    numPaquetOrd += 1;
                    this.fluxTCPordonne.add( this.fluxTCP.get(i) ) ;
                }
                else if ( this.fluxTCP.get(i).numSequence == this.fluxTCPordonne.get( numPaquetOrd ).numAcquit ){
                    numPaquetOrd += 1;
                    this.fluxTCPordonne.add( this.fluxTCP.get(i) ) ;
                   }
                else{
                    for ( int j = 0 ; j < numPaquetOrd ; j ++ ){
                        if ( this.fluxTCP.get(i).numAcquit == this.fluxTCPordonne.get( j ).numSequence + this.fluxTCPordonne.get( j ).size - this.fluxTCPordonne.get( j ).sizeEnTete * 4 + 1){
                            numPaquetOrd += 1;
                            this.fluxTCPordonne.add( this.fluxTCP.get(i) ) ;
                        }
                    }
                }
            }

            // recherche de la condition de fin
            // les deux derniers paquets du flux comportent les flags [FIN] puis [ACK]
            if ( this.fluxTCPordonne.get( numPaquetOrd ).flagACK && this.fluxTCPordonne.get( numPaquetOrd - 1 ).flagFIN ){
                continuer = false ;
            }
        limitMax++ ;
        }//while
    }


    public void afficherFlux(){

        PaquetDHCP paquetDHCP ;
        PaquetDNSoverTCP paquetDNSoverTCP ;
        PaquetHTTP paquetHTTP ;
        PaquetFTP paquetFTP ;

        for ( int i = 0 ; i < this.fluxTCPordonne.size() ; i ++ ){
            System.out.println();
            System.out.printf( ">>> No %d  |  ------------------------------------------------------------------ >>>\n\n", this.fluxTCPordonne.get( i ).numPaquet ) ;
            this.fluxTCPordonne.get( i ).affichPaquetTCP( true ) ;

            // DHCP
            if (( this.fluxTCPordonne.get( i ).portDest == 67 || this.fluxTCPordonne.get( i ).portSource == 67 ) && this.fluxTCPordonne.get( i ).size > this.fluxTCPordonne.get( i ).sizeEnTete * 4 ){
                paquetDHCP = new PaquetDHCP( this.fluxTCPordonne.get( i ).dataTCP ) ;
                paquetDHCP.affichPaquetDHCP( true ) ;
            }
            //DNS
            else if (( this.fluxTCPordonne.get( i ).portDest == 53 || this.fluxTCPordonne.get( i ).portSource == 53 ) && this.fluxTCPordonne.get( i ).size > this.fluxTCPordonne.get( i ).sizeEnTete * 4 ){
                paquetDNSoverTCP = new PaquetDNSoverTCP( this.fluxTCPordonne.get( i ).dataTCP ) ;
                paquetDNSoverTCP.affichPaquetDNS( true ) ;
            }
            //HTTP
            else if (( this.fluxTCPordonne.get( i ).portDest == 80 || this.fluxTCPordonne.get( i ).portSource == 80 ) && this.fluxTCPordonne.get( i ).size > this.fluxTCPordonne.get( i ).sizeEnTete * 4 ){
                paquetHTTP = new PaquetHTTP( this.fluxTCPordonne.get( i ).dataTCP ) ;
                paquetHTTP.affichPaquetHTTP( true ) ;
            }
            //FTP
            else if (( this.fluxTCPordonne.get( i ).portDest == 21 || this.fluxTCPordonne.get( i ).portSource == 21) && this.fluxTCPordonne.get( i ).size > this.fluxTCPordonne.get( i ).sizeEnTete * 4 ){
                paquetFTP = new PaquetFTP( this.fluxTCPordonne.get( i ).dataTCP ) ;
                paquetFTP.affichPaquetFTP( true ) ;
            }
            // FTP mode passif
            else if ( ( this.fluxTCPordonne.get( i ).portDest == this.port1 || this.fluxTCPordonne.get( i ).portSource == this.port1 ) && this.fluxTCPordonne.get( i ).size > this.fluxTCPordonne.get( i ).sizeEnTete * 4 ){
                paquetFTP = new PaquetFTP( this.fluxTCPordonne.get( i ).dataTCP ) ;
                paquetFTP.affichPaquetFTP( true ) ;
            }
            
        }
    }
}
