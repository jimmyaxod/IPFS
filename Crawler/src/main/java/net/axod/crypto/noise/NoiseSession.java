package net.axod.crypto.noise;

//import javax.crypto.Cipher;
//import javax.crypto.SecretKey;
//import javax.crypto.spec.ChaCha20ParameterSpec;

/**
 * A Noise Session can be used to talk noise.
 *
 */
public class NoiseSession {
    private static final String ENCRYPT_ALGO = "ChaCha20";
	
	public NoiseSession() {
		
	}

/*
    public byte[] encrypt(byte[] pText, SecretKey key, byte[] nonce, int counter) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);

        cipher.init(Cipher.ENCRYPT_MODE, key, param);

        byte[] encryptedText = cipher.doFinal(pText);

        return encryptedText;
    }

    public byte[] decrypt(byte[] cText, SecretKey key, byte[] nonce, int counter) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);

        cipher.init(Cipher.DECRYPT_MODE, key, param);

        byte[] decryptedText = cipher.doFinal(cText);

        return decryptedText;

    }
*/
}