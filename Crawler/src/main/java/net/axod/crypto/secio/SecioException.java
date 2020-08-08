package net.axod.crypto.secio;

/**
 * Something went wrong with Secio
 *
 */
public class SecioException extends Exception {

	public SecioException(String msg) {
		super(msg);	
	}
	
	public String toString() {
		return "SecioException " + super.toString();	
	}
}