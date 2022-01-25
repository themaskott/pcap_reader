// classe PatquetICMP
// traitement des ICMP - longeur d entete 16 octets


//  0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11| 12| 13| 14| 15| 16| 17| 18| 19| 20| 21| 22| 23| 24| 25| 26| 27| 28| 29| 30| 31|      
// ---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
//        Type message            |        Code                   |               Somme de controle
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                    Bourrage ou donnees
// ---------------------------------------------------------------|----------------------------------------------------------------
//                                    Donnees (optionnel, longeur variable)
// ---------------------------------------------------------------|----------------------------------------------------------------


public class PaquetICMP {

    int type = 0 ;
    int code = 0 ;

    PaquetICMP( String[] paquetICMP ){

        // recuperation du type et du code de message ICMP
        this.type = Integer.parseInt( String.join("", Fonctions.extractArray( paquetICMP, 0, 0, false )), 16 ) ;
        this.code = Integer.parseInt( String.join("", Fonctions.extractArray( paquetICMP, 1, 2, false )), 16 ) ;

    }



    public void affichPaquetICMP( boolean verbose ){
        System.out.println( "-----+-----> [\033[1;32m+\033[0m] ICMP" ) ;
        System.out.println( "-----+-----> Message : " + convertCodeICMP(this.type, this.code));
    }



    // convertCodeICMP
    // compose le message correspondant aux combinaison possibles de types et de codes ICMP
    public static String convertCodeICMP( int type, int code ){
        String messageICMP = "" ;

        switch( type ){
            
            case 0:
                messageICMP = "ECHO reply" ;
                break ;
            
            case 3:
                messageICMP = "Destinataire inaccessible" ; 
                switch ( code ){
                    case 0:
                        messageICMP += " / Le reseau n est pas accessible" ;
                        break ;
                    case 1:
                        messageICMP += " / La machine n est pas accessible" ;
                        break ;                   
                    case 2:
                        messageICMP += " / Le protocole n est pas accessible" ;
                        break ;
                    case 3:
                        messageICMP += " / La port n est pas accessible" ;
                        break ; 
                    case 4:
                        messageICMP += " / Fragmentation necessaire mais impossible a cause du drapeau DF" ;
                        break ;
                    case 5:
                        messageICMP += " / Le routage a echoue" ;
                        break ;
                    case 6:
                        messageICMP += " / Reseau inconnu" ;
                        break ;
                    case 7:
                        messageICMP += " / Machine inconnue" ;
                        break ;                   
                    case 8:
                        messageICMP += " / Machine non connectee au reseau" ;
                        break ;
                    case 9:
                        messageICMP += " / Communication avec le reseau interdite" ;
                        break ; 
                    case 10:
                        messageICMP += " / Communication avec la machine interdite" ;
                        break ;
                    case 11:
                        messageICMP += " / Reseau inaccessible pour ce service" ;
                        break ;
                    case 12:
                        messageICMP += " / Machine inaccessible pour ce service" ;
                        break ;
                    case 13:
                        messageICMP += " / Communication interdite" ;
                        break ; 
                    case 14:
                        messageICMP += " / Priorite d hote viole" ;
                        break ;
                    case 15:
                        messageICMP += " / Limite de priorite atteinte" ;
                        break ;
                    default:
                        messageICMP += "" ;
                        break ;
                }
                break ;

            case 4:
                messageICMP = "Extincion de la source" ;
                break;       

            case 5:
                messageICMP = "Redirection" ;
                switch ( code ){
                    case 0:
                        messageICMP += " / Redirection pour un hote" ;
                        break ;
                    case 1:
                        messageICMP += " / Redirection pour un hote et un service" ;
                        break ;                   
                    case 2:
                        messageICMP += " / Redirection pour un reseau" ;
                        break ;
                    case 3:
                        messageICMP += " / Redirection pour un reseau et un service" ;
                        break ;
                    default:
                        messageICMP += "" ;
                        break ;
                }               
                break ;
     
            case 8:
                messageICMP = "ECHO request" ;
                break ;
            case 11:
                messageICMP = "Temps depasse" ;
                break ;
            case 12:
                messageICMP = "Entete errone" ;
                break ;
            case 13:
                messageICMP = "Demande heure" ;
                break ;
            case 14:
                messageICMP = "Reponse heure" ;
                break ;
            case 15:
                messageICMP = "Demande adresse IP" ;
                break ;
            case 16:
                messageICMP = "Reponse adresse IP" ;
            case 17:
                messageICMP = "Demande masque de sous reseau" ;
                break ;
            case 18:
                messageICMP = "Reponse masque de sous reseau" ;
                break ;
            default:
                messageICMP = "Inconnu" ;
                break;
        }

        return messageICMP ;
    }

}
