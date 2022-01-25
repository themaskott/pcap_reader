
// classe PaquetDHCP
// traitement du paquet DHCP decapsule d UDP/IP


// Entete DHCP


//  0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11| 12| 13| 14| 15| 16| 17| 18| 19| 20| 21| 22| 23| 24| 25| 26| 27| 28| 29| 30| 31|      
// ---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
//           operation            |  hardware address type        | hardware address lenght       |        hops
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                        xid
// ---------------------------------------------------------------|----------------------------------------------------------------
//                 temps (en sec) depuis requete client           |      flags
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            adresse IP du client (si existante)
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            future (?) adresse IP du client 
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            adresse IP du prochain serveur a utiliser
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            adresse IP de la passerelle
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            adresse hardware du client ....
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            ...adresse hardware du client ...
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            ...adresse hardware du client ...
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            ...adresse hardware du client
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            nom du serveur (optionnel) 64 octets
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            fichier (128 octets)
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            options
// ---------------------------------------------------------------|----------------------------------------------------------------


// todo : prise en compte autre type d adresses hardware, gestion des differentes adresses IP (future, serveur, passerelle)
// todo : ameliorer le traitemnet des options (type de requete/reponse, hostname, ...) actuellement formate en string pour affichage
// --> attributs de l objet pour manipulation

public class PaquetDHCP {

    int opcode = 0 ;
    int addressType = 0 ;
    int addressLenght = 0 ;
    long xid = 0 ;
    String xidHexa = "" ;
    int timeSec = 0 ;
    String clientIPaddress = "" ;
    String clientFutureIPaddress = "" ;
    String clientMACaddress = "" ;
    String[] optionsDHCP ;

    int size ;

    PaquetDHCP( String[] paquetDHCP ){

        // recuperation de l operation
        this.opcode = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDHCP, 0, 0, false )), 16 ) ;

        // recuperation du type d adresse hardware
        this.addressType = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDHCP, 1, 1, false )), 16 ) ;

        // recuperation de la taille de l adresse hardware
        this.addressLenght = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDHCP, 2, 2, false )), 16 ) ;

        // recuperation du nombre aleatoire choisi par le client = transaction ID / en long et en hexa (affichage)
        this.xid = Long.parseLong( String.join("", Fonctions.extractArray( paquetDHCP, 4, 7, false )), 16 ) ;
        this.xidHexa = "0x" + String.join("", Fonctions.extractArray( paquetDHCP, 4, 7, false )) ;

        // recuperation de l adresse IP courante du client
        this.clientIPaddress = Fonctions.convertToIPaddress( Fonctions.extractArray( paquetDHCP, 12, 15, false )) ;

        // recuperation de la future adresse IP du client
        this.clientFutureIPaddress = Fonctions.convertToIPaddress( Fonctions.extractArray( paquetDHCP, 16, 19, false )) ;

        // recuperation de l adresse MAC du client - si autre type que MAC utiliser [28:28 + addressLenght -1 ] 
        this.clientMACaddress = String.join(":", Fonctions.extractArray( paquetDHCP, 28, 28 + this.addressLenght - 1, false )) ;

        // recuperation des options ( taille totale - entetes 11*4+64+128 )
        this.size = paquetDHCP.length ;
        this.optionsDHCP = new String[ paquetDHCP.length - 236 ] ;
        this.optionsDHCP = Fonctions.extractArray( paquetDHCP, 236, paquetDHCP.length -1 , false )  ;

    }


    public void affichPaquetDHCP( boolean verbose ){

        System.out.println( "-----+-----+-----> [\033[1;32m+\033[0m] DHCP" ) ;
        System.out.println( "-----+-----+-----> Operation : " + operationDHCP( this.opcode ) ) ;
        System.out.println( "-----+-----+-----> Transaction ID : " + this.xidHexa ) ;
        System.out.println( "-----+-----+-----> Adresse IP client : " + this.clientIPaddress ) ;
        System.out.println( "-----+-----+-----> Future adresse IP client : " + this.clientFutureIPaddress ) ;       
        System.out.println( "-----+-----+-----> Adresse MAC du client : " + this.clientMACaddress ) ;
        
        if (verbose ){
            System.out.println( parseOptionsDHCP( this.optionsDHCP ) );
        }
    }

    // operationDHCP
    // fait correspondre le code DHCP a sa denomination
    public static String operationDHCP( int opcode ){
        String operation = "" ;

        if ( opcode == 1 ){
            operation = "BOOTREQUEST" ;
        }
        else if ( opcode == 2 ){
            operation = "BOOTREPLY" ;
        }
        return operation ;
    }

    // parseOptionsDHCP
    // traitement du champ des options DHCP - commence par le magic cookie 0x63825363
    // renvoi sous forme de String les options pour leur affichage
    //
    //  ------------------------------------------------------------------------------------------------------------------------------
    // | 63 | 82 | 53 | 63 | n°option1 | long n1 | n1 octets de champs ... | n°option2 | long n2 | n2 octets de champs ... | ... | FF |
    //  -------------------|----------------------------------------------------------------------------------------------------------
    //    magic cookie     |                   option 1                    |                   option 2
    //
    public static String parseOptionsDHCP( String[] optionsDHCPH ){

        String optionsPourAffichage = "" ;

        // pointeur sur le rang de l option a lire
        int indiceOption = 0 ;
        int valOption = 0 ;
        int sizeOption = 0 ;

        // recuperation du magic cookie et test de sa valeur avant traitemnet des autres options
        String magicCookie = String.join("", Fonctions.extractArray( optionsDHCPH, 0, 3, false )) ;

        if ( magicCookie.equals("63825363") ){

            // pointe sur la premiere option
            indiceOption = 4 ; 
            // recuperation de la valeur de l option pointee
            valOption = Integer.parseInt( String.join( "", Fonctions.extractArray( optionsDHCPH, indiceOption, indiceOption, false )) , 16 ) ;
            
            // FF flag de fin d options
            while ( valOption != Integer.parseInt("FF", 16) ){

                // recuperation de la longeur des champs de l option
                sizeOption = Integer.parseInt( String.join( "", Fonctions.extractArray( optionsDHCPH, indiceOption + 1, indiceOption + 1, false )) , 16 ) ;                
                
                // 53 : DHCP Discover
                if ( valOption == 53 ){
                    optionsPourAffichage += "-----+-----+-----> Option (53) DHCP discover : " ;
                    int typeDiscover = Integer.parseInt( String.join("", Fonctions.extractArray( optionsDHCPH, indiceOption + 2, indiceOption + 2, false )), 16 ) ;
                    switch( typeDiscover ){
                        case 1:
                            optionsPourAffichage += "DHCPDISCOVER\n" ;
                            break ;
                        case 2:
                            optionsPourAffichage += "DHCPOFFER\n" ;
                            break ;
                        case 3:
                            optionsPourAffichage += "DHCPREQUEST\n" ;
                            break ;
                        case 4:
                            optionsPourAffichage += "DHCPDECLINE\n" ;
                            break ;
                        case 5:
                            optionsPourAffichage += "DHCPACK\n" ;
                            break ;
                        case 6:
                            optionsPourAffichage += "DHCPNAK\n" ;
                            break ;
                        case 7:
                            optionsPourAffichage += "DHCPRELEASE\n" ;
                            break ;
                        case 8:
                            optionsPourAffichage += "DHCPINFORM\n" ;
                            break ;
                    }
                }
                // 57 : Maximum message size
                else if ( valOption == 57 ){
                    optionsPourAffichage += "-----+-----+-----> Option (57) Maximum message size : " ;
                    int messageSize = Integer.parseInt( String.join("", Fonctions.extractArray( optionsDHCPH, indiceOption + 2, indiceOption + 2 + sizeOption -1 , false )), 16 ) ;
                    optionsPourAffichage += messageSize + "\n" ;
                }
                // 12 : Host Name
                else if ( valOption == 12 ){
                    optionsPourAffichage += "-----+-----+-----> Option (12) Host name : " ;
                    optionsPourAffichage += Fonctions.affichDataASCII( Fonctions.extractArray( optionsDHCPH, indiceOption + 2, indiceOption + 2 + sizeOption -1 , false ) ) ;
                }

                // incrementation du pointeur sur la prochaine option (1 octet option + 1 octet size + size )
                indiceOption += 2 + sizeOption ;

                // recuperation de la valeur de l option pointee
                valOption = Integer.parseInt( String.join( "", Fonctions.extractArray( optionsDHCPH, indiceOption, indiceOption, false )) , 16 ) ;
            } 
        }
        return optionsPourAffichage ;
    }
    
}
