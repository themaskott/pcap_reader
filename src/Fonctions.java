import java.io.* ;

// class Fonctions
// fonctions utiles dans le reste du programme

public class Fonctions {

    // showMenu
    // affiche le menu d aide et quitte
    public static void showMenu(){

        System.out.println( "PcapReader, version 1.0" ) ;
        System.out.println() ;
        System.out.println( "usage : java PcapReader -f file.pcap" ) ;
        System.out.println() ;
        System.out.println( "\t-h : affiche cette aide" ) ;
        System.out.println( "\t-f : fichier pcap a analyser" ) ;
        System.out.println( "\t-v : mode verbose, affiche plus d informations sur les paquets" ) ;
        System.out.println( "\t-x : contenu, affiche les paquets captures en hexa" ) ;


        System.exit(0) ;
    }
        
    // readOctets
    // in : flux de donnees (fichier en cours de lecture) et nombre d octets a lire depuis la position courante de lecture
    // out : octets lu en tableau de string hexa
    public static String[] readOctetsHex( DataInputStream pcapFile, int nbOctets ) {

        byte octetLu ;
        int octetPositif ;
        String[] tabOctets = new String[ nbOctets ];
        int teteLecture = 0 ;
        try {
    
            while ( teteLecture < nbOctets ) {
                octetLu = pcapFile.readByte();
                octetPositif = (int) octetLu & 0xFF ; // octet entre -128 et 127, repasse entre 0 et 255
                tabOctets[teteLecture] = String.format("%02X", octetPositif) ;
                teteLecture += 1 ;
            }
        } catch (EOFException eof) {
            // fin normale de la lecture
            System.out.println();
        } catch (IOException ioe) {
            System.err.println(ioe);
            System.exit(1);
        }
    return tabOctets ;    
    }

    // inverseTab
    // in : tableau de String
    // out : 
    // inverse un tableau de String
    // /!\ modifie le tableau d origine
    public static void inverseTab( String[] tab ){

        for(int i=0 ; i< tab.length/2; i++){
            String tmp = tab[i];
            tab[i] = tab[tab.length-i-1];
            tab[tab.length-i-1] = tmp;
        }
    }

    // extractArray
    // in : un tableau de String, les indices de debut et de fin, un boolean 
    // out : un tableau de String extrait du tableau d entree, inverse si swapped est vrai
    // /!\ on utlise les indices des tableau de 0 a taille-1
    public static String[] extractArray( String[] tab, int iStart, int iEnd, boolean swapped ){
        String[] tabTmp = new String[ iEnd - iStart +1 ] ;

        for ( int i = 0 ; i < iEnd - iStart + 1 ; i++ ){
            tabTmp[i] = tab[ iStart + i ] ;
        }
        if ( swapped ) {
            inverseTab( tabTmp );
        }
        return tabTmp ;
    }


    // convertToIPaddress
    // renvoi un tableau de 4 entiers (octets) sous la forme d une adresse IP 
    public static String convertToIPaddress( String[] tab ){

        String IPadress = "" ;
        IPadress = Integer.toString( Integer.parseInt( tab[0], 16 )) + "." + Integer.toString( Integer.parseInt( tab[1], 16 )) + "." + Integer.toString( Integer.parseInt( tab[2], 16 )) + "." + Integer.toString( Integer.parseInt( tab[3], 16 )) ;
        return IPadress ;
    }

    // convertToIPaddressV6
    // retroune un tableau de 16 octets sous forme d une adresse IPv6
    public static String convertToIPaddressv6( String[] tab ){
        
        String IPadress = "" ;

        for ( int i = 0 ; i < tab.length - 1 ; i++ ){

            if ( i % 2 == 1){
                IPadress += tab[i] + ":" ;
            }
            else{
                IPadress += tab[i] ; 
            }
        }
        IPadress += tab[ tab.length -1 ] ;
        return IPadress ;
    }

    // affichDataASCII
    // affiche un tableau de chaine hexa sous forme ASCII
    // in : tableau d octets en hexa
    public static String affichDataASCII( String[] datas ){
        int size = datas.length ;
        String datasAscii = "" ;
        char tmp ;

        for ( int i = 0 ; i < size ; i++ ){
            tmp = (char) Integer.parseInt( datas[i], 16 ) ;
            if ( Character.isLetterOrDigit(tmp) ){
                datasAscii += tmp ;
            }
            else if ( tmp == '\n' || tmp == '\r' || tmp == '<' || tmp == '>' || tmp == '/' || tmp == '(' || tmp == ')'){
                datasAscii += tmp ; ;
            }
            else {
                datasAscii += "." ;
            }
        }
        return datasAscii ;        
    } 


    // affichDataHexa
    // affichage des paquets sous forme hexa groupes par 8 octets
    // in : tableau de strings hexa
    // out :
    // >>> Contenu du paquet >>>
    // 08 00 27 C9 C8 40 08 00    27 AA E7 9E 08 00 45 00    ...ÉÈ...    .ªç...E.
    // 00 4E 7E 99 00 00 40 11    E8 03 0A 00 00 02 0A 00    .N......    è.......
    // 00 01 E9 BF 00 35 00 3A    CE 5E 7F 39 01 20 00 01    ..é..5..    Î..9....
    // 00 00 00 00 00 01 06 67    6F 6F 67 6C 65 02 66 72    .......g    oogle.fr
    // 00 00 01 00 01 00 00 29    10 00 00 00 00 00 00 0C    ........    ........
    // 00 0A 00 08 45 E1 BC 07    C0 00 35 E0....Eá..                    À.5à

    public static void affichDataHexa( String[] datas ){
        int size = datas.length ;
        int nbPaquet16 = size / 16 ;
        int reliquat = size % 16 ;

        System.out.println() ;
        System.out.println( ">>> Contenu brut de la capture >>>" ) ;

        // nb de paquets de 16 octets en 2 groupes de 8
        for ( int i = 0 ; i < nbPaquet16 ; i++ ){
            // partie hexa
            System.out.print( String.join( " ", extractArray( datas, (i*16) + 0, (i*16) + 7, false ))) ;
            System.out.print( "    " ) ;
            System.out.print( String.join( " ", extractArray( datas, (i*16) + 8, (i*16) + 15, false ))) ;
            System.out.print( "    " ) ;
            // partie ASCII
            System.out.print( affichDataASCII( extractArray( datas, (i*16) + 0, (i*16) + 7, false ) ));
            System.out.print( "    " ) ;
            System.out.print( affichDataASCII( extractArray( datas, (i*16) + 8, (i*16) + 15, false ) ));
            System.out.println() ;
        }
        // cas du reliquat
        if ( reliquat <= 8 ){
            System.out.print( String.join( " ", extractArray( datas, nbPaquet16*16, size - 1, false ))) ;
            // decale du nb d espace pour aligner l affichage
            System.out.print( " ".repeat((54 - String.join( " ", extractArray( datas, nbPaquet16*16, size - 1, false )).length() ))) ;
            System.out.print( affichDataASCII( extractArray( datas, nbPaquet16*16, size - 1, false ) ));
            System.out.println() ;
        }
        else {
            // partie hexa
            System.out.print( String.join( " ", extractArray( datas, nbPaquet16*16, nbPaquet16*16 + 7, false ))) ;
            System.out.print( "    " ) ;
            System.out.print( String.join( " ", extractArray( datas, nbPaquet16*16 + 8, size - 1, false ))) ;
            // partie ASCII
            // decale du nb d espace pour aligner l affichage
            System.out.print( " ".repeat((27 - String.join( " ", extractArray( datas, nbPaquet16*16 + 8, size - 1, false )).length() ))) ;
            System.out.print( affichDataASCII( extractArray( datas, nbPaquet16*16, nbPaquet16*16 + 7, false ) ));
            System.out.print( "    " ) ;
            System.out.print( affichDataASCII( extractArray( datas, nbPaquet16*16 + 8, size - 1, false ) ));
            System.out.println() ;
        }
    }
}
