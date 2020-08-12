package net.axod.crypto.keys;

import io.ipfs.multihash.*;

import java.security.*;
import java.util.*;

public class KeyManager {
	static HashMap<String, KeyPair> keys = new HashMap();	// Cache of name -> keypair
	
	/**
	 * Generates a new keypair, or gets an existing one from the cache...
	 *
	 */
	public static KeyPair getKeyPair(String name) {
		KeyPair kp = keys.get(name);
		if (kp==null) {
			kp = getNewKeys();
			keys.put(name, kp);
		}
		return kp;
	}


	// My RSA keys
	static KeyPair mykeys = null;	

	static {
		mykeys = getNewKeys();
	}

	public static KeyPair getNewKeys() {
        KeyPair kp = null;
		try {
        	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        	SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        	keyGen.initialize(2048, random);

        	kp = keyGen.generateKeyPair();
        } catch(Exception e) {
        	System.err.println("Can't generate keys! " + e);
        	System.exit(-1);
        }
        return kp;
	}
	
	/**
	 * Get a keypair to use. For now we just create one...
	 *
	 */
	public static KeyPair getKeys() {
		return mykeys;	
	}
	
	/**
	 * Given a public key, we can get a Multihash which shows the PeerID in a
	 * more usable format.
	 *
	 */
	public static Multihash getPeerID(byte[] pubkey) {
		Multihash h;

		// Let's work out their ID...
		if (pubkey.length<=42) {
			// Use identity multihash
			h = new Multihash(Multihash.Type.id, pubkey);
		} else {
			// Use sha2-256
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(pubkey);
				byte[] digest = md.digest();
				h = new Multihash(Multihash.Type.sha2_256, digest);
				
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e.getMessage(), e);
			}								
		}
		return h;
	}
}