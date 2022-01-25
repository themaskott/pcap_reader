import java.util.* ;
import java.io.* ;

// classe PaquetHeaders
// extrait les headers attaches au paquet capture - 16 octets

// structure :
// typedef struct pcaprec_hdr_s {
//     guint32 ts_sec;         /* timestamp seconds */
//     guint32 ts_usec;        /* timestamp microseconds */
//     guint32 incl_len;       /* number of octets of packet saved in file */
//     guint32 orig_len;       /* actual length of packet */
// } pcaprec_hdr_t;

// le constructeur necessite en parametre le flux en cours de lecture
// ainsi que le boleen swapped pour l inverion ou non des octets

public class PaquetHeaders {
    
    // taille du header du fichier pcap
    final static int SIZEOF_PAQUET_HEADER = 16 ;

    // headers recupere en tableau de string hexa
    String[] tabHeaders = new String[ SIZEOF_PAQUET_HEADER ] ;

    int timestampUTM = 0 ;
    int timestampCapture = 0 ;
    int paquetSize = 0 ;
    int originSize = 0 ;

    Date date ;

    PaquetHeaders ( DataInputStream pcapFile, boolean swapped ) {

        // recuperation du header du paquet dans un tableau
        this.tabHeaders = Fonctions.readOctetsHex( pcapFile, SIZEOF_PAQUET_HEADER ) ;        

        // recuperation du timestamp
        this.timestampUTM = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 0, 3, swapped) ), 16 ) ;
        this.timestampCapture = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 4, 7, swapped ) ), 16 ) ;
        
        this.date = new Date( (long) this.timestampUTM * 1000 ) ;

        // recuperation de la taille du paquet (capture et origine)
        this.paquetSize = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 8, 11, swapped ) ), 16 ) ;
        this.originSize = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 12, 15, swapped ) ), 16 ) ;

    }


    // affichPaquetHeaders
    // affiche les valeurs des chunks du header de paquet, informations lies a la capture
    public void affichPaquetHeaders( boolean verbose ){
        System.out.println("[\033[1;32m+\033[0m] Information de capture") ;
        System.out.println( "GDH de capture : " + this.date );
        System.out.printf( "Taille du paquet capture : %d\n", this.paquetSize ) ;
        
        if ( verbose ){
            System.out.printf( "Epoch de capture (sec) : %d\n", this.timestampUTM ) ;
            System.out.printf( "TimeStamp debut capture (micro.s) : %d\n", this.timestampCapture ) ;
            System.out.printf( "Taille d origine : %d\n", this.originSize ) ;
        }
        System.out.println() ;

    }

}
