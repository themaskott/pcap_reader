import java.util.* ;

// FragmentationIP
// instancie une liste de paquet IP qui enregistre les paquets IP rencontres en parsant le pcap
// identifie les paquets comportant le marqeur de fragmentation
// reconstitue les paquets originaux grace a leur identifiant et l offset des donnees dans le paquet original

public class FragmentationIP {
    
    List<PaquetIPv4> paquetIPv4List ;

    FragmentationIP( ){
        this.paquetIPv4List = new ArrayList<PaquetIPv4>() ;
    }

    public void ajoutPaquet( PaquetIPv4 paquetIPv4 ){
        this.paquetIPv4List.add( paquetIPv4 ) ;
    }

    
    // reconstitue un paquet fragmente a partie de son identifiant
    public  void reconstituerUnPaquet( int identifiant ){

        PaquetIPv4 [] tabPaquetIPv4 ;
        int nbFragments = 0 ;
        int sizeNewPaquet = 0 ;

        // nombre de fragments correspondants a l'idetifiant
        for ( int i = 0 ; i < this.paquetIPv4List.size() ; i++ ){
            if ( this.paquetIPv4List.get(i).identificationFragment == identifiant ){
                nbFragments += 1 ;
            }
        }

        // tableau recevant les fragments correspondants a l identifiant
        tabPaquetIPv4 = new PaquetIPv4[ nbFragments ] ;

        // parcours de la liste pour extraire les paquets correspondants a l identifiant et les stocker dans le tableau
        // en meme temps pour chaque paquet calcul du volume de donnees transportes (i.e taille du fragement de la couche superieure)
        // incrementation de sizeNewPaquet pour avoir la taille finale du paquet reconstitue
        int tmp = 0 ;
        for ( int i = 0 ; i < this.paquetIPv4List.size() ; i++ ){
            if ( this.paquetIPv4List.get(i).identificationFragment == identifiant ){
                tabPaquetIPv4[ tmp ] = this.paquetIPv4List.get(i) ;
                sizeNewPaquet += this.paquetIPv4List.get(i).longueurTotale - this.paquetIPv4List.get(i).longueurEnTete ;
                tmp++ ;
            }      
        }

        // tableau pour concatener les fragments
        String[] datasConcatene = new String[ sizeNewPaquet ] ;

        // parcours des paquets IP
        for ( int i = 0 ; i < nbFragments ; i++ ){
            // pour chaque paquet i, parcours des donnees qu il transporte avec j
            // les donnees sont recopiees dans datasConcatene au bon offset
            tmp = 0 ;
            for ( int j = 0 ; j < tabPaquetIPv4[i].longueurTotale - tabPaquetIPv4[i].longueurEnTete ; j++ ){

                datasConcatene[ tabPaquetIPv4[i].fragmentOffset + tmp ] = tabPaquetIPv4[i].dataIPv4[j] ;
                tmp++ ;

            }
        }

        // selon le protocole transporte par IP, instanciation d un objet de la classe correspondante a partir de datasConcatene
        if ( tabPaquetIPv4[0].numProtocole == 1 ){
            PaquetICMP paquetICMPreconstitue = new PaquetICMP( datasConcatene ) ;
            tabPaquetIPv4[0].affichePaquetIPv4( true ) ;
            paquetICMPreconstitue.affichPaquetICMP( true ) ;
        }
        else if ( tabPaquetIPv4[0].numProtocole == 6 ){
            PaquetTCP paquetTCPreconstitue = new PaquetTCP( datasConcatene ) ;
            tabPaquetIPv4[0].affichePaquetIPv4( true ) ;
            paquetTCPreconstitue.affichPaquetTCP( true ) ;
        }
        else if ( tabPaquetIPv4[0].numProtocole == 17 ){
            PaquetUDP paquetUDPreconstitue = new PaquetUDP( datasConcatene ) ;
            tabPaquetIPv4[0].affichePaquetIPv4( true ) ;
            paquetUDPreconstitue.affichPaquetUDP( true ) ;
        }

    }

    public void reconstituerTousPaquet( String identifiants ){
        String[] tabIdentifiants = identifiants.split(" ") ;
        int numIdentifiant = 0 ;

        for( String id: tabIdentifiants ){
            numIdentifiant = Integer.parseInt( id ) ;
            reconstituerUnPaquet( numIdentifiant );
        }

    }

    // utilisee pour debuggage
    // public void affichListe( boolean verbose ){
    //     // this.paquetIPv4List[0].affichePaquetIPv4() ;
    //     for ( int i = 0 ; i < this.paquetIPv4List.size() ; i++ ){
    //         this.paquetIPv4List.get(i).affichePaquetIPv4( verbose ) ;
    //     }
    // }

}
