package Kerberos;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Client-Klasse
 */

import java.util.*;

public class Client extends Object {

	private KDC myKDC;

	private Server myFileserver;

	private String currentUser;

	private Ticket tgsTicket = null;

	private long tgsSessionKey; // K(C,TGS)

	private Ticket serverTicket = null;

	private long serverSessionKey; // K(C,S)

	// Konstruktor
	public Client(KDC kdc, Server server) {
		myKDC = kdc;
		myFileserver = server;
	}

	public boolean login(String userName, char[] password) {
        System.out.println("Client#login");

        // what is the nonce good for? it's not part of the official kerberos protocol
        TicketResponse ticketResponse = myKDC.requestTGSTicket(userName, myKDC.getName(), generateNonce());

        boolean success = false;

        if (ticketResponse.decrypt(generateSimpleKeyForPassword(password))) {
            tgsSessionKey = ticketResponse.getSessionKey();
            tgsTicket = ticketResponse.getResponseTicket();

            // remove password from memory
            Arrays.fill(password, (char) 0);

            success = true;
        } else {
            System.out.println("*** could not decrypt ticket response");
        }

        return success;
	}

	public boolean showFile(String serverName, String filePath) {
	// TODO!!
        System.out.println("Client#showFile");
        return false;
	}

	/* *********** Hilfsmethoden **************************** */

	private long generateSimpleKeyForPassword(char[] pw) {
		// Liefert einen Schl�ssel f�r ein Passwort zur�ck, hier simuliert als
		// long-Wert
		long pwKey = 0;
		for (int i = 0; i < pw.length; i++) {
			pwKey = pwKey + pw[i];
		}
		return pwKey;
	}

	private long generateNonce() {
		// Liefert einen neuen Zufallswert
		long rand = (long) (100000000 * Math.random());
		return rand;
	}
}
