// classe PaquetTCP
// traitement du paquet TCP decapsule d IP


// Segment TCP


//  0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11| 12| 13| 14| 15| 16| 17| 18| 19| 20| 21| 22| 23| 24| 25| 26| 27| 28| 29| 30| 31|      
// ---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
//                  Port source                                   |                   Port destination
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                        Numero de sequence
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                        Numero acquittement
// ---------------------------------------------------------------|----------------------------------------------------------------
// taille entete | reserve    |ECN|CWR|ECE|URG|ACK|PSH|RST|SYN|FIN|                     Fenetre 
// ---------------------------------------------------------------|----------------------------------------------------------------
//                 Somme de controle                              |                  Pointeur de donnees urgentes
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                        options + remplissage
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                            donnees
// 


// todo : gestion des flag de l entete autres que ACK PUSH RST SYN FIN


public class PaquetTCP {
    
    int portSource = 0 ;
    int portDest = 0 ;
    long numSequence = 0 ;
    long numAcquit = 0 ;
    int sizeEnTete = 0 ;
    int flagsTCP = 0 ;
    boolean flagACK = false ;
    boolean flagSYN = false ;
    boolean flagFIN = false ;

    String[] dataTCP ;
    int size = 0 ;

    // utilise par PcapReader pour retrouver les paquets dans le follow TCP
    int numPaquet = 0 ;

    PaquetTCP( String[] paquetTCP ){

        // longueur du paquet TCP
        this.size = paquetTCP.length ;

        // recuperation du port source
        this.portSource = Integer.parseInt( String.join("", Fonctions.extractArray( paquetTCP, 0, 1, false )), 16 ) ;
        
        // recuperation du port destination
        this.portDest = Integer.parseInt( String.join("", Fonctions.extractArray( paquetTCP, 2, 3, false )), 16 ) ;
        
        // recuperation du numero de sequence
        this.numSequence = Long.parseLong( String.join("", Fonctions.extractArray( paquetTCP, 4, 7, false )), 16 ) ;
        
        // recuperation du numero d acquittement
        this.numAcquit = Long.parseLong( String.join("", Fonctions.extractArray( paquetTCP, 8, 11, false )), 16 ) ;

        // recuperation de la taille de l entete
        this.sizeEnTete = Integer.parseInt( String.join("", Fonctions.extractArray( paquetTCP, 12, 12, false )), 16 ) >> 4 ;

        // recuperation des flags (partiel)
        this.flagsTCP = ( Integer.parseInt( String.join("", Fonctions.extractArray( paquetTCP, 13, 13, false )), 16 ) << 27 ) >>> 27 ;

        // recuperation des donnees transportees (/!\taille entete x32bits)
        this.dataTCP = new String[ paquetTCP.length - this.sizeEnTete * 4 ] ;
        this.dataTCP = Fonctions.extractArray( paquetTCP, this.sizeEnTete * 4, paquetTCP.length - 1 , false ) ;

    }

    public void affichPaquetTCP( boolean verbose ){
    
        System.out.println( "-----+-----> [\033[1;32m+\033[0m] TCP" ) ;
        System.out.printf( "-----+-----> Port Source : %d\n", this.portSource ) ;
        System.out.printf( "-----+-----> Port Dest : %d\n", this.portDest ) ;
        System.out.printf( "-----+-----> Num de séquence : %d\n", this.numSequence ) ;
        System.out.printf( "-----+-----> Num acquittement : %d\n", this.numAcquit ) ;
        System.out.printf( "-----+-----> Taille de l'entete : %d (x32bits)\n", this.sizeEnTete ) ;
        System.out.println( "-----+-----> Falgs : " + parseFlags( flagsTCP )) ;
    }


    // parseFlags
    // in : un entier correspondant a l octet des flags du segment TCP
    // out : une string correspondant a ces flags
    // les decalages servent a isoler les bits marquants ces flags
    // /!\ decalages a droite avec >>> pour ne pas tenir compte du signe
    public String parseFlags ( int flagsTCP ){
        String flags = "" ;

        if ( flagsTCP >> 4 == 1 ){
            this.flagACK = true ;
            flags += "[ACK]" ;
        }
        if ( (flagsTCP << 28) >>> 31 == 1 ){
            flags += "[PSH]" ;
        }
        if ( (flagsTCP << 29) >>> 31 == 1 ){
            flags += "[RST]" ;
        }      
        if ( (flagsTCP << 30) >>> 31 == 1 ){
            this.flagSYN = true ;
            flags += "[SYN]" ;
        }
        if ( (flagsTCP << 31) >>> 31 == 1 ){
            this.flagFIN = true ;
            flags += "[FIN]" ;
        }

        return flags ;
    }



}
