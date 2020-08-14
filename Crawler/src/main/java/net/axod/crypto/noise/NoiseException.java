package net.axod.crypto.noise;

/**
 * Something went wrong within the Noise protocol...
 *
 */
public class NoiseException extends Exception {

	public NoiseException(String msg) {
		super(msg);	
	}
}