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
		// Login prŸfen: TGS-Ticket vorhanden?
		// Serverticket vorhanden? Wenn nicht, neues Serverticket anfordern (Schritt 3: requestServerTicket) und Antwort auswerten
		// Service beim Server anfordern (Schritt 5: requestService)
		System.out.println("Client#showFile");
		return false;
	}

	/* *********** Hilfsmethoden **************************** */

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
