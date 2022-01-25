// classe PaquetIPv4
// traitement du parquet IPv4 decapsule d ethernet

// En tete IP v4

//  0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11| 12| 13| 14| 15| 16| 17| 18| 19| 20| 21| 22| 23| 24| 25| 26| 27| 28| 29| 30| 31|      
// ---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
//   vesion IP    |  long entete  |    type service               |                   long totale
// ---------------------------------------------------------------|----------------------------------------------------------------
//      identification                                            | indicateur|    Fragment offset
// ---------------------------------------------------------------|----------------------------------------------------------------
//    TTL                         |          protocole            |               CRC
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                         Adresse source
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                         Adresse destination
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                        options + remplissage
// ---------------------------------------------------------------|----------------------------------------------------------------



public class PaquetIPv4 {

    int versionIP = 0 ;
    int longueurEnTete = 0 ;
    int longueurTotale = 0 ;
    int identificationFragment = 0 ;
    int indicateur = 0 ;
    int fragmentOffset = 0 ;
    int ttl = 0 ;
    int numProtocole = 0 ;
    String typeProtocole = "" ;
    String adresseSource ;
    String adresseDest ;
    String[] dataIPv4 ;

    PaquetIPv4( String[] paquetIPv4 ){

        // recuperation de la version IP
        this.versionIP = Integer.parseInt( String.join("", Fonctions.extractArray( paquetIPv4, 0, 0, false ) ), 16 ) >>> 4 ;

        // recuperation de la longueur de l en tete, donnee en nombre de mots de 32 bits
        this.longueurEnTete = ( ( Integer.parseInt( String.join("", Fonctions.extractArray( paquetIPv4, 0, 0, false ) ), 16 ) << 28 ) >>> 28 ) * 4 ;

        // recuperation de la longueur totale
        this.longueurTotale = Integer.parseInt( String.join("", Fonctions.extractArray( paquetIPv4, 2, 3, false ) ), 16 ) ;

        // recuperation de l identifiant du fragment
        this.identificationFragment = Integer.parseInt( String.join("", Fonctions.extractArray( paquetIPv4, 4, 5, false ) ), 16 ) ;
       
        // recuperation de l indicateur de fragmentation (3e bit des 3 bits indicateurs)
        this.indicateur = ( Integer.parseInt( String.join("", Fonctions.extractArray( paquetIPv4, 6, 7, false ) ), 16 ) << 18 ) >>> 31 ;

        // recuperation du fragment offset (en nombre de paquets de 8 octets)
        this.fragmentOffset = (( Integer.parseInt( String.join("", Fonctions.extractArray( paquetIPv4, 6, 7, false ) ), 16 ) << 19 ) >>> 19 ) * 8;

        // recuperation du TTL
        this.ttl = Integer.parseInt( String.join("", Fonctions.extractArray( paquetIPv4, 8, 9, false ) ), 16 ) >> 8 ;

        // recuperation du protocole
        this.numProtocole = ( Integer.parseInt( String.join("", Fonctions.extractArray( paquetIPv4, 8, 9, false ) ), 16 ) << 24 ) >>> 24 ;

        switch( this.numProtocole ){
   
            case 1: 
                this.typeProtocole = "ICMP" ;
                break;
        
            case 2:
                this.typeProtocole = "IGMP" ;
                break;
        
            case 6:
                this.typeProtocole = "TCP" ;
                break;

            case 17:
                this.typeProtocole = "UDP" ;
                break;

            default:
                this.typeProtocole = "Protocole non supporte" ;
                break;
        }

        // recuperation de l adresse source
        this.adresseSource = Fonctions.convertToIPaddress( Fonctions.extractArray( paquetIPv4, 12, 15, false )) ;
    
        // recuperation de l adresse dest
        this.adresseDest = Fonctions.convertToIPaddress( Fonctions.extractArray( paquetIPv4, 16, 19, false )) ;

        // recuperation des datas transposportees (ie paquet couche superieure) 20o = taille entete sans champ option
        this.dataIPv4 = new String [ paquetIPv4.length - 20 ] ;
        this.dataIPv4 = Fonctions.extractArray( paquetIPv4, 20, paquetIPv4.length - 1, false ) ;
    }


    public void affichePaquetIPv4( boolean verbose ){

        System.out.println( "-----> [\033[1;32m+\033[0m] IPv4" ) ;
        System.out.println( "-----> Protocole: " + this.typeProtocole ) ;
        System.out.println( "-----> IP source : " + this.adresseSource) ;
        System.out.println( "-----> IP destination : " + this.adresseDest ) ;
        if ( this.indicateur == 1 ){
            System.out.println( "-----> Paquet fragmente") ;
        }

        if ( verbose ){
            System.out.printf( "-----> Version IP : %d\n", this.versionIP ) ;
            System.out.printf( "-----> TTL: %d\n", this.ttl ) ;
            System.out.printf( "-----> Longueur de l entete : %d octets\n", this.longueurEnTete ) ;
            System.out.printf( "-----> Longeur totale : %d octets\n", this.longueurTotale ) ;
            System.out.printf( "-----> Identification du fragment : %d\n", this.identificationFragment ) ;
            System.out.printf( "-----> Indicateur: %d\n", this.indicateur ) ;
            System.out.printf( "-----> Fragment offset: %d\n", this.fragmentOffset ) ;
            System.out.printf( "-----> Num Protocole: %d\n", this.numProtocole ) ;
        }
        //System.out.println( Arrays.toString( this.dataIPv4 ))   ;        

    }
    
}
