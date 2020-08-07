package net.axod.crypto.keys;

import java.security.*;

public class KeyManager {
	// My RSA keys
	static KeyPair mykeys = null;	

	static {
        // TODO: Allow reusing previous keys. These should be stored and reused.
        try {
        	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        	SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        	keyGen.initialize(2048, random);

        	mykeys = keyGen.generateKeyPair();

        } catch(Exception e) {
        	System.err.println("Can't generate keys! " + e);
        	System.exit(-1);
        }		
	}

	/**
	 * Get a keypair to use. For now we just create one...
	 *
	 */
	public static KeyPair getKeys() {
		return mykeys;	
	}
}