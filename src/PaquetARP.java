

// classe PatquetARP
// traitement des ARP - longeur d entete 28 octets


//  0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11| 12| 13| 14| 15| 16| 17| 18| 19| 20| 21| 22| 23| 24| 25| 26| 27| 28| 29| 30| 31|      
// ---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
//                  Type network                                  |                   Protocole type
// ---------------------------------------------------------------|----------------------------------------------------------------
//    harware length              |     logical address lenght    |               Operation
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                        Sender Hardware Adress ...
// ---------------------------------------------------------------|----------------------------------------------------------------
//    ...sender hardware address                                  |         Sender internet address ....
// ---------------------------------------------------------------|----------------------------------------------------------------
//    ... sender internet address                                 |                  Target hardware address ...
// ---------------------------------------------------------------|----------------------------------------------------------------
//    ...  target hardware address
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                  Target internet address
// ---------------------------------------------------------------|----------------------------------------------------------------



public class PaquetARP {
    
    int networkType = 0 ;
    int protocoleType = 0 ;
    int hardwareLenght = 0 ;
    int logicalAddressLenght = 0 ;
    int opcode = 0 ;
    String senderHardwareAddress = "" ;
    String senderInternetAddress = "" ;
    String destHardwareAddress = "" ;
    String destInternetAddress = "" ;
    

    PaquetARP( String[] paquetARP ){

        //recuperation du type de reseau
        this.networkType = Integer.parseInt( String.join("", Fonctions.extractArray( paquetARP, 0, 1, false )), 16 ) ;

        // recuperation du protocole
        this.protocoleType = Integer.parseInt( String.join("", Fonctions.extractArray( paquetARP, 2, 3, false )), 16 ) ;

        // recuperation de la taille d adresse physique
        this.hardwareLenght = Integer.parseInt( String.join("", Fonctions.extractArray( paquetARP, 4, 4, false )), 16 ) ;

        // recuperation de la taille d adresse logique
        this.logicalAddressLenght = Integer.parseInt( String.join("", Fonctions.extractArray( paquetARP, 5, 5, false )), 16 ) ;

        // recuperation du type d operation
        this.opcode = Integer.parseInt( String.join("", Fonctions.extractArray( paquetARP, 6, 7, false )), 16 ) ;

        // recuperation de l adresse MAC emetrice
        this.senderHardwareAddress = String.join(":", Fonctions.extractArray( paquetARP, 8, 13, false )) ;

        // recuperation de l adresse IP emetrice
        this.senderInternetAddress = Fonctions.convertToIPaddress( Fonctions.extractArray( paquetARP, 14, 17, false )) ;
        
        // recuperation de l adresse MAC destinataire
        this.destHardwareAddress = String.join(":", Fonctions.extractArray( paquetARP, 18, 23, false )) ;

        // recuperation de l adresse IP destinataire
        this.destInternetAddress = Fonctions.convertToIPaddress( Fonctions.extractArray( paquetARP, 24, 27, false )) ;

    }



    public void affichPaquetARP( boolean verbose ){

        System.out.println( "-----> [\033[1;32m+\033[0m] ARP" ) ;
        System.out.println( "-----> Operation : " + operationARP( this.opcode ) ) ;
        System.out.println( "-----> Adresse MAC source : " + this.senderHardwareAddress ) ;
        System.out.println( "-----> Adresse IP source : " + this.senderInternetAddress ) ;
        System.out.println( "-----> Adresse MAC dest : " + this.destHardwareAddress ) ;
        System.out.println( "-----> Adresse IP dest : " + this.destInternetAddress ) ;
        
        if ( verbose ){
            System.out.printf( "-----> Type de reseau : %d\n", this.networkType ) ;
            System.out.printf( "-----> Protocole appelant : %d\n", this.protocoleType ) ;
        }

    }

    // operationARP
    // fait correspondre le code ARP a sa denomination
    public static String operationARP( int opcode ){
        String operation = "" ;

        if ( opcode == 1 ){
            operation = "ARP request" ;
        }
        else if ( opcode == 2 ){
            operation = "ARP response" ;
        }

        return operation ;
    }

}
