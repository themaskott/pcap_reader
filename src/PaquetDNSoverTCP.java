
// classe PaquetDNS
// traitement du paquet DNS decapsule d TCP/IP 


// Entete DNS sur TCP precedee de 2 octets nomme « longueur »
// il permet de specifier la la longueur total des donnees independamment de la fragmentation. La longueur est calcule sans les 2 octets de ce meme champ


//  0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11| 12| 13| 14| 15| 16| 17| 18| 19| 20| 21| 22| 23| 24| 25| 26| 27| 28| 29| 30| 31|      
// ---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
//                         Identification                         | QR|    opcode     | AA| TC| RD| RA| Z | AD| CD|   Rcode      
// ---------------------------------------------------------------|----------------------------------------------------------------
//                         Total questions                        |                      Total answers
// ---------------------------------------------------------------|----------------------------------------------------------------
//                 Total authority ressource records              |      Total additional ressource records
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            Question Section
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            Answer Section 
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            Authority Section
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                            Additionnal Section
// ---------------------------------------------------------------|----------------------------------------------------------------

// todo : reconstitution de paquet tronques
// todo ! champs question / answer


public class PaquetDNSoverTCP {

    int indentification = 0 ;
    int qr = 0 ;
    int opcode = 0 ;
    int rCode = 0 ;
    int qdCount = 0 ;
    int anCount = 0 ;
    int nsCount = 0 ;
    int arCount = 0 ;
    String[] datasDNS ;
    int longueur = 0 ;


    PaquetDNSoverTCP ( String[] paquetDNS ){

        // recuperation de la longueur
        this.longueur = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDNS, 0, 1, false )), 16 ) ;

        // recuperation de l identification
        this.indentification = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDNS, 2, 3, false )), 16 ) ;

        // recuperation de QR et opcode
        this.qr = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDNS, 4, 4, false )), 16 ) >>> 7 ;
        this.opcode = ( Integer.parseInt( String.join("", Fonctions.extractArray( paquetDNS, 4, 4, false )), 16 ) << 17 ) >>> 28 ;

        // recuperation Rcode 
        this.rCode = ( Integer.parseInt( String.join("", Fonctions.extractArray( paquetDNS, 5, 5, false )), 16 ) << 28 ) >>> 28 ;


        // recuperation des differents compteurs
        this.qdCount = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDNS, 6, 7, false )), 16 ) ;
        this.anCount = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDNS, 8, 9, false )), 16 ) ;
        this.nsCount = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDNS, 10, 11, false )), 16 ) ;
        this.arCount = Integer.parseInt( String.join("", Fonctions.extractArray( paquetDNS, 12, 13, false )), 16 ) ;
        
        // recuperation des donnes transportees dans la requete
        this.datasDNS = Fonctions.extractArray( paquetDNS, 14, paquetDNS.length - 1, false) ;

    }


    public void affichPaquetDNS ( boolean verbose ){

        System.out.println( "-----+-----+-----> [\033[1;32m+\033[0m] DNS" ) ;
        System.out.println( "-----+-----+-----> Operation : " + operationDNS( this.qr, this.opcode ) ) ;
        // Affichage des champs Qestion Reponse
        System.out.println(parseQRDNS(this.datasDNS, this.qr, this.qdCount, this.anCount, this.nsCount));


    }

    // traitement de l operation DNS ( question ou reponse )
    public static String operationDNS( int qr, int opcode ){
        String operation = "" ;

        if ( qr == 1 ){
            operation = "Reponse DNS" ;
        }
        else if ( qr == 0 ){
            operation = "Requete DNS - " ;
            if ( opcode == 0 ){
                operation += "Standard" ;
            }
            else if ( opcode == 1 ){
                operation += "Inverse" ;
            }
            else if ( opcode == 2 ){
                operation += "Status serveur" ;
            }
        }
        return operation ;
    }

    // traitement des donnes transportees
    public static String parseQRDNS( String[] datasDNS, int qr, int qdCount, int anCount, int nsCount ){
            
            // concatenation des valeurs pour l affichage final 
            String dataAffich = "" ;
            int size = 0 ;
            int ptr = 0 ;

            // generique
            int typeRR = 0 ;
            int classeRR = 0 ;
            int typeNS = 0 ;
            int classeNS = 0 ;
            long ttl = 0 ;
            int datalenght = 0 ;
            String ipAdress = "" ;
            int i = 0 ;

            // lie au NameServer
            long nsSerialNumber = 0 ;
            long nsRefresh = 0 ;
            long nsRetry = 0 ;
            long nsExpire = 0 ;
            String primaryNS = "" ;
            String respMail = "" ;
            String nsName = "" ;

            // champ questions
            String qName = "" ;

            // champ reponses
            String rName = "" ;


            // cas d une question
            // | 1o | value n octets | 00 | typeRR 1o | classeRR 1o |
            if ( qr == 0 ){

                dataAffich += "-----+-----+-----> Nombre de questions : " + qdCount + "\n" ;

                ptr = 0 ;
                size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr, false )), 16 ) ;
                
                qName = getLabel( datasDNS, ptr ) ;

                ptr += qName.length() ;

                typeRR = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 1, ptr + 2, false )), 16 ) ;
                classeRR = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 3, ptr + 4, false )), 16 ) ;
                dataAffich += "-----+-----+-----> Nom : " + qName ;
                dataAffich += " | Type : " + typeCorrespondance( typeRR ) ;
                dataAffich += " | Classe : " + classeCorrespondance( classeRR ) + "\n" ;

            }
            // cas d une reponse
            else if ( qr == 1 ){
                
                // reprise de la question en debut des datas :
                dataAffich += "-----+-----+-----> Nombre de questions : " + qdCount + "\n" ;

                ptr = 0 ;

                size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr, false )), 16 ) ;

                qName = getLabel( datasDNS, ptr ) ;

                ptr += qName.length() ;

                typeRR = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 1, ptr + 2, false )), 16 ) ;
                classeRR = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 3, ptr + 4, false )), 16 ) ;
                
                dataAffich += "-----+-----+----->    Nom : " + qName ;
                dataAffich += " | Type : " + typeCorrespondance( typeRR ) ;
                dataAffich += " | Classe : " + classeCorrespondance( classeRR ) + "\n" ;
                
                // recuperation des reponses
                dataAffich += "-----+-----+-----> Nombre de reponses : " + anCount + "\n" ;

                // decalage du ptr : 00 + 2o type + 2o classe
                ptr += 5 ;
                    
                for ( int nbQ = 0 ; nbQ < anCount ; nbQ ++ ){

                    size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr, false )), 16 ) ;

                    if ( size < 192 ){
                        rName = getLabel( datasDNS, ptr ) ;
                        ptr = avancePtr( datasDNS, ptr ) ;
                    }
                    else{
                        i = ( Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr + 1 , false )), 16 ) << 18 ) >>> 18  ;
                        i = i - 12 ;
                        rName = getLabel( datasDNS, i ) ;
                        ptr = avancePtr( datasDNS, ptr ) ;
                    }
                    
                    dataAffich += "-----+-----+----->    Nom : " + rName  ;

                    typeRR = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr + 1, false )), 16 ) ;
                    classeRR = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 2, ptr + 3, false )), 16 ) ;
                    ttl =  Long.parseLong( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 4, ptr + 7, false )), 16 ) ;
                    datalenght = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 8, ptr + 9, false )), 16 ) ;

                    

                    dataAffich += " | Type : " + typeCorrespondance( typeRR ) ;
                    dataAffich += " | Classe : " + classeCorrespondance( classeRR ) ;
                    dataAffich += " | TTL : " + ttl ;
                    dataAffich += " | Data Lenght : " + datalenght ;
                    
                    ptr += 10 ;

                    // value : si typeRR  = A -> adresse IP, AAAA -> IPv6, sinon (CNAME) --> label
                    if ( typeRR == 1){
                        ipAdress = Fonctions.convertToIPaddress( Fonctions.extractArray( datasDNS, ptr, ptr + 3, false ) );
                        dataAffich += " | Adresse : " + ipAdress + "\n";
                        ptr += datalenght ;
                    }
                    else if ( typeRR == 28 ){
                        ipAdress = Fonctions.convertToIPaddressv6( Fonctions.extractArray( datasDNS, ptr, ptr + 15, false) ) ;
                        dataAffich += " | Adresse : " + ipAdress + "\n";
                        ptr += datalenght ;
                    }
                    else{
                        size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr, false )), 16 ) ;

                        if ( size < 192 ){
                            rName = getLabel( datasDNS, ptr ) ;
                            ptr += datalenght ;
                        }
                        else{
                            i = ( Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr + 1 , false )), 16 ) << 18 ) >>> 18  ;
                            i = i - 12 ;
                            rName = getLabel( datasDNS, i ) ;
                            ptr += datalenght ;
                        }
                        dataAffich += " | " + typeCorrespondance(typeRR) + " : " + rName + "\n" ;
                    }

                }

            }

            // recuperation des Authoritative NameServeur si present

            for ( int nbNS = 0 ; nbNS < nsCount ; nbNS++ ){

                dataAffich += "-----+-----+-----> Nombre de serveurs autoritaires : " + nsCount + "\n" ;

                size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr, false )), 16 ) ;
                if ( size < 192 ){
                    nsName = getLabel( datasDNS, ptr ) ;
                    ptr = avancePtr( datasDNS, ptr ) ;
                }
                else{
                    i = ( Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr + 1 , false )), 16 ) << 18 ) >>> 18  ;
                    i = i - 12 ;
                    nsName = getLabel( datasDNS, i ) ;
                    ptr = avancePtr( datasDNS, ptr ) ;
                }

                dataAffich += "-----+-----+----->    Nom : " + nsName ;

                typeNS = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr + 1, false )), 16 ) ;
                classeNS = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 2, ptr + 3, false )), 16 ) ;
                ttl =  Long.parseLong( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 4, ptr + 7, false )), 16 ) ;
                datalenght = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 8, ptr + 9, false )), 16 ) ;

                dataAffich += " | Type : " + typeCorrespondance( typeNS ) ;
                dataAffich += " | Classe : " + classeCorrespondance( classeNS ) ;
                dataAffich += " | TTL : " + ttl ;
                dataAffich += " | Data Lenght : " + datalenght ;

                ptr += 10 ;

                size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr, false )), 16 ) ;
                if ( size < 192 ){
                    primaryNS = getLabel( datasDNS, ptr ) ;
                    ptr = avancePtr( datasDNS, ptr ) ;
                }
                else{
                    i = ( Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr + 1 , false )), 16 ) << 18 ) >>> 18  ;
                    i = i - 12 ;
                    primaryNS = getLabel( datasDNS, i ) ;
                    ptr = avancePtr( datasDNS, ptr ) ;
                }

                size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr, false )), 16 ) ;
                if ( size < 192 ){
                    respMail = getLabel( datasDNS, ptr ) ;
                    ptr = avancePtr(datasDNS, ptr) ;
                }
                else{
                    i = ( Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr + 1 , false )), 16 ) << 18 ) >>> 18  ;
                    i = i - 12 ;
                    respMail = getLabel( datasDNS, i ) ;
                    ptr = avancePtr( datasDNS, ptr ) ;
                }

                dataAffich += " | Primary Name Server : " + primaryNS ;
                dataAffich += " | Responsible authorithy's mailbox : " + respMail ;

                nsSerialNumber = Long.parseLong( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr + 3, false )), 16 ) ;
                nsRefresh = Long.parseLong( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 4, ptr + 7, false )), 16 ) ;
                nsRetry = Long.parseLong( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 8, ptr + 11, false )), 16 ) ;
                nsExpire = Long.parseLong( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 12, ptr + 15, false )), 16 ) ;
                ttl = Long.parseLong( String.join( "" , Fonctions.extractArray( datasDNS, ptr + 16, ptr + 19, false )), 16 ) ;


                dataAffich += " | Numero de serie : " + nsSerialNumber ;
                dataAffich += " | Rafraichissemnent : " + nsRefresh ;
                dataAffich += " | Retry interval : " + nsRetry ;
                dataAffich += " | Expire : " + nsExpire ;
                dataAffich += " | TTL minimum : " + ttl + "\n" ;                

            }

            return dataAffich ;
    }


    // avance le pointeur dans datas selon le type de label lu (pointeur ou label)
    public static int avancePtr( String[] datasDNS, int ptr ){

        int size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr, false )), 16 ) ;

        while ( size != 0 ){ 
            if ( size >= 192 ){
                return ptr + 2 ;
            }
            else{
                ptr += size + 1 ; 
                size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, ptr, ptr, false )), 16 ) ;    
            }
        }
        return ptr + 1  ;

    }
  
    // recupere un lablel ( toto.foo.bar ) a partir d en emplacement dans les datas a l offset ptr
    // si data[ptr] < 192 -> le lablel dabute  a la position suivante
    // sinon la position suivante pointe sur un autre offset contenant le label
    public static String getLabel( String[] datasDNS, int ptr ){
        String name = "" ;
        int size = 0 ;
        int i = 0 ;
        int j = 0 ;
        
        i = ptr ;

        size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, i, i, false )), 16 ) ;
        while ( size != 0 ){

            if ( size < 192){
                i ++ ;
                name += Fonctions.affichDataASCII( Fonctions.extractArray( datasDNS, i, i + size - 1, false )) + "." ;
                i += size ;
                size = Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, i, i, false )), 16 ) ;
                }
            else{
                j = ( Integer.parseInt( String.join( "" , Fonctions.extractArray( datasDNS, i, i + 1 , false )), 16 ) << 18 ) >>> 18  ;
                j = j - 12 ;
                name += getLabel( datasDNS, j ) ;
                // todo : ameliorer sortie de boucle, 1 seul pointeur suivi
                size = 0 ;
            }
        }
        return name ;
    }

    // correspondance des types de RR
    public static String typeCorrespondance( int typeRR ){
        String typeRRclair = "" ;
        // todo : autres valeurs
        switch( typeRR ){
            case 1:
                typeRRclair = "A" ;
                break ;
            case 2:
                typeRRclair = "A" ;
                break ;
            case 5:
                typeRRclair = "CNAME" ;
                break ;
            case 6:
                typeRRclair = "SOA" ;
                break; 
            case 15:
                typeRRclair = "MX" ;
                break ;
            case 16:
                typeRRclair = "TXT" ;
                break ;
            case 28:
                typeRRclair = "AAAA";
                break ;
        }
        return typeRRclair ;
    }

    // correspondance des classes de RR
    public static String classeCorrespondance( int classeRR ) {
        String classeRRclair = "" ;
        switch( classeRR ){
            case 1:
                classeRRclair = "IN" ;
                break ;
            case 2:
                classeRRclair = "CSNET" ;
                break ;
            case 3:
                classeRRclair = "CHAOS" ;
                break ;
            case 4:
                classeRRclair = "HESIOD" ;
                break ;
        }
        return classeRRclair ;
    }
}