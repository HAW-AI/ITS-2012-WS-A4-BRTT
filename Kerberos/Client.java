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

		long nonce = generateNonce();
		TicketResponse ticketResponse = myKDC.requestTGSTicket(userName,
				myKDC.getName(), nonce);

		boolean success = false;

		if (ticketResponse != null) {
			logGood("received ticket response");

			if (ticketResponse.decrypt(generateSimpleKeyForPassword(password))) {
				logGood("decrypted ticket response");

				if (ticketResponse.getNonce() == nonce) {
					logGood("validated nonce from response");

					currentUser = userName;
					tgsSessionKey = ticketResponse.getSessionKey();
					tgsTicket = ticketResponse.getResponseTicket();

					// remove password from memory
					Arrays.fill(password, (char) 0);

					success = true;
				} else {
					logBad("could not validate nonce from response");
				}
			} else {
				logBad("could not decrypt ticket response");
			}
		} else {
			logBad("did not receive ticket response (wrong user or server)");
		}

		return success;
	}

	public boolean showFile(String serverName, String filePath) {
		boolean success = false;
		Ticket serverTicket = null;
		
		System.out.println("Client#showFile");
		
		// Login prŸfen: TGS-Ticket vorhanden?
		if (getTGSTicket() != null ) {
			
			// Serverticket vorhanden? Wenn nicht, neues Serverticket anfordern (Schritt 3: requestServerTicket) und Antwort auswerten
			if ((serverTicket = getServerTicket(serverName)) != null) {
				Auth auth = buildAuth();
				auth.encrypt(serverSessionKey);
				
				// Service beim Server anfordern (Schritt 5: requestService)
				success = myFileserver.requestService(serverTicket, auth, "showFile", filePath);
			}
		}
		return success;
	}

	/* *********** Hilfsmethoden **************************** */

	private Auth buildAuth() {
		return new Auth(currentUser, (new Date()).getTime());
	}
	
	private Ticket getTGSTicket() {
		if (tgsTicket.equals(null)) {
			// build tgsTicket?
		}
		return tgsTicket;
	}
	
	private Ticket getServerTicket(String serverName) {
		if (serverTicket == null) {
			// build serverTicket
			Auth auth = buildAuth();
			auth.encrypt(tgsSessionKey);
			
			TicketResponse ticket = myKDC.requestServerTicket(getTGSTicket(), auth, serverName, generateNonce());
			if (ticket.decrypt(tgsSessionKey)) {
				serverTicket = ticket.getResponseTicket();
				serverSessionKey = ticket.getSessionKey();
				serverTicket.print();
			}
		}
		return serverTicket;
	}
	
	private long generateSimpleKeyForPassword(char[] pw) {
		// Liefert einen Schlï¿½ssel fï¿½r ein Passwort zurï¿½ck, hier simuliert
		// als
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

	private void logGood(String msg) {
		System.out.println("*** good: " + msg);
	}

	private void logBad(String msg) {
		System.out.println("*** bad: " + msg);
	}
}
