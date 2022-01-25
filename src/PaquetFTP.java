
// classe PaquetFTP
// traitement du paquet FTP decapsule de TCP/IP 

// Les commandes et retour serveur sont en texte ASCII termine par un CRLF
// On recherche un retour debutant par le code 227 qui signale le port utilise pour le tranfert de fichiers
// Ce port est recuperer par la boucle principale de PcapReader afin de traiter aussi les echanges sur celui ci


public class PaquetFTP {
    
    String[] tabTmp ;
    String [] ftpDataServerIPPport ;
    String ftpDataServerIP = "" ;
    int ftpDataServerPort = 0 ;


    // constructeur vide, pour pouvoir detecter si un port est propose lors du parsing du pcap
    PaquetFTP(){
        this.ftpDataServerPort = 0 ;
    }


    PaquetFTP ( String[] paquetFTP ){

        this.tabTmp = Fonctions.affichDataASCII(paquetFTP).split("\r\n") ; 

        // detection d une reponse a une demande de passive mode
        // requete : PASV
        // reponse : 227.Entering.Passive.Mode.(192.168.0.193.28.86)
        // 192.168.0.193 est l ip du server de fichiers
        // 28 * 256 + 86 = 7254 est le port a utiliser
        //
        if ( this.tabTmp[0].startsWith("227") ){
            this.ftpDataServerIPPport = this.tabTmp[0].substring( this.tabTmp[0].indexOf("(") + 1 , this.tabTmp[0].indexOf(")")  ).split("[.]") ;
            this.ftpDataServerIP = this.ftpDataServerIPPport[0] + "." + this.ftpDataServerIPPport[1] + "." + this.ftpDataServerIPPport[2] + "." + this.ftpDataServerIPPport[3]  ;
            this.ftpDataServerPort = Integer.parseInt( this.ftpDataServerIPPport[4] ) * 256 + Integer.parseInt( this.ftpDataServerIPPport[5] ) ;
        }
        
    }

    public void affichPaquetFTP( boolean verbose ){

        System.out.println( "-----+-----+-----> [\033[1;32m+\033[0m] FTP" ) ;
        System.out.println( "-----+-----+-----> Message : " + this.tabTmp[0] );
        if ( this.ftpDataServerPort != 0 ){
            System.out.println( "-----+-----+-----> Adresse IP du serveur de fichier : " + this.ftpDataServerIP ) ;
            System.out.println( "-----+-----+-----> Port du serveur de fichier : " + this.ftpDataServerPort ) ;
        }
    }
        
}
