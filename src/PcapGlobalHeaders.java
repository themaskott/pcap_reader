import java.io.* ;

// classe PcapGlobalHeaders
// extrait les headers du fichiers pcap - 24 octets

// structure du header :
// typedef struct pcap_hdr_s {
//    guint32 magic_number;   /* magic number */
//    guint16 version_major;  /* major version number */
//    guint16 version_minor;  /* minor version number */
//    gint32  thiszone;       /* GMT to local correction */
//    guint32 sigfigs;        /* accuracy of timestamps */
//    guint32 snaplen;        /* max length of captured packets, in octets */
//    guint32 network;        /* data link type */
// } pcap_hdr_t;


public class PcapGlobalHeaders {

    // taille du header du fichier pcap
    final static int SIZEOF_PCAP_GLOBAL_HEADER = 24 ;
    
    // headers recupere en tableau de string hexa
    String[] tabHeaders = new String[ SIZEOF_PCAP_GLOBAL_HEADER ] ;
    boolean swapped = false ;
    String magicNumber ;
    int versionMajeure = 0 ;
    int versionMineure = 0 ;
    int timeThisZone = 0 ;
    int timeSigFigs = 0 ;
    int snaplen = 0 ; 
    int network = 0 ;

    PcapGlobalHeaders( DataInputStream pcapFile ){
        // recuperation du header fichier dans un tableau
        this.tabHeaders = Fonctions.readOctetsHex( pcapFile, SIZEOF_PCAP_GLOBAL_HEADER ) ;        
        
        // extraction du magic number
        this.magicNumber = String.join("", Fonctions.extractArray(this.tabHeaders, 0, 3, false) ) ;

        // test du magic number swapped ou non / todo : reaction aux autres magic number
        if ( this.magicNumber.equals( "D4C3B2A1" )){
            this.swapped = true ;
        }
        else if ( this.magicNumber.equals( "A1B2C3D4" ) ){
            this.swapped = false ;
        }
        else{
            System.out.println( "Format de capture non supporte" ) ;
            System.exit( 0 ) ;
        }

        // extraction de la version
        this.versionMajeure = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 4, 5, this.swapped) ), 16 ) ;
        this.versionMineure = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 6, 7, this.swapped) ), 16 ) ;

        // extratcion des timestamp
        this.timeThisZone = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 8, 11, this.swapped) ), 16 ) ;
        this.timeSigFigs = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 12, 15, this.swapped) ), 16 ) ;

        // extraction de la taille max des paquets captures
        this.snaplen = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 16, 19, this.swapped) ), 16 ) ;

        // extraction du type de lien rzo
        this.network = Integer.parseInt( String.join("", Fonctions.extractArray( this.tabHeaders, 20, 23, this.swapped) ), 16 ) ;
    }


    // affichPcapHeaders
    // affiche les valeurs des chunk du header du fichier pcap
    public void affichPcapHeaders(){

        System.out.println("[\033[1;32m+\033[0m] HEADERS DU FICHIER PCAP") ;
        System.out.println() ;
        System.out.println( "Magic Number : " + this.magicNumber ) ;
        System.out.printf( "Version majeure : %d\n", this.versionMajeure ) ;
        System.out.printf( "Version mineure : %d\n", this.versionMineure ) ;
        System.out.printf( "Time this zine : %d\n", this.timeThisZone ) ;
        System.out.printf( "Time sigfigs : %d\n", this.timeSigFigs ) ;
        System.out.printf( "Taille max : %d\n", this.snaplen ) ;
        System.out.printf( "Type de lien : %d\n", this.network ) ;
        System.out.println( "-----------------------------------" ) ;
        System.out.println() ;

    }

} 