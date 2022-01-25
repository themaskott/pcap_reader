
// classe PaquetHTTP
// traitement du paquet HTTP decapsule de TCP/IP
// Recupere et affiche l entete HTTP (1er bloc avant le double CRLF) 

public class PaquetHTTP {
    
    String[] tabTmp ;
    String headersHTTP = "" ;

    PaquetHTTP ( String[] paquetHTTP ){

        this.tabTmp = Fonctions.affichDataASCII(paquetHTTP).split("\r\n\r\n") ; 
        
    }

    public void affichPaquetHTTP( boolean verbose ){

        System.out.println( "-----+-----+-----> [\033[1;32m+\033[0m] HTTP" ) ;
        
        if ( this.tabTmp[0].startsWith("HTTP") ){
            System.out.println("-----+-----+-----> Reponse HTTP :") ;
            System.out.println( this.tabTmp[0] ) ;
        }
        else if ( this.tabTmp[0].startsWith("GET") || this.tabTmp[0].startsWith("POST") || this.tabTmp[0].startsWith("PUT") || this.tabTmp[0].startsWith("DELETE") || this.tabTmp[0].startsWith("HEAD") || this.tabTmp[0].startsWith("OPTIONS") || this.tabTmp[0].startsWith("TRACE") ){
            System.out.println("-----+-----+-----> Requete HTTP :") ;
            System.out.println( this.tabTmp[0] ) ;
        }
        else{
            System.out.println("-----+-----+-----> Datas HTTP") ;
        }
        
        if ( verbose ){
            for( String f: this.tabTmp ){
                System.out.println( f ) ;
            }
        }

    }

}
