// classe PaquetUDP
// traitement du paquet UDP decapsule d IP


// Paquet UDP - entete = 8 octets


//  0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11| 12| 13| 14| 15| 16| 17| 18| 19| 20| 21| 22| 23| 24| 25| 26| 27| 28| 29| 30| 31|      
// ---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
//                  Port source                                   |                   Port destination
// ---------------------------------------------------------------|----------------------------------------------------------------
//                   Longueur                                     |                     Somme de controle
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                                            donnees
// 



public class PaquetUDP {
    
    int portSource = 0 ;
    int portDest = 0 ;
    int size = 0 ;
    String[] dataUDP ;

    PaquetUDP ( String[] paquetUDP ){

        // recuperation du port source
        this.portSource = Integer.parseInt( String.join("", Fonctions.extractArray( paquetUDP, 0, 1, false )), 16 ) ;

        // recuperation du port destination
        this.portDest = Integer.parseInt( String.join("", Fonctions.extractArray( paquetUDP, 2, 3, false )), 16 ) ;

        // recuperation de la taille totale (entete + donnees)
        this.size = Integer.parseInt( String.join("", Fonctions.extractArray( paquetUDP, 4, 5, false )), 16 ) ;

        // recuperation des donnees transportees
        this.dataUDP = new String[ this.size - 8 ] ;
        this.dataUDP = Fonctions.extractArray( paquetUDP, 8, paquetUDP.length - 1 , false ) ;

    }

    public void affichPaquetUDP( boolean verbose ){

        System.out.println( "-----+-----> [\033[1;32m+\033[0m] UDP" ) ;
        System.out.printf( "-----+-----> Port Source : %d\n", this.portSource ) ;
        System.out.printf( "-----+-----> Port Dest : %d\n", this.portDest ) ;
    }


}
