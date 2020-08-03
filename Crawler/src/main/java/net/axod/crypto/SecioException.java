package net.axod.crypto;

public class SecioException extends Exception {

	public SecioException(String msg) {
		super(msg);	
	}
	
	public String toString() {
		return "SecioException " + super.toString();	
	}
}