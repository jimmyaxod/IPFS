package net.axod.protocols;

import com.google.protobuf.*;

import net.axod.*;

import java.nio.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;

import javax.crypto.*;
import javax.crypto.spec.*;


public class SecioHelper {

	static SecioProtos.Propose local_propose;
	static SecioProtos.Propose remote_propose;
	static SecioProtos.Exchange local_exchange;
	static SecioProtos.Exchange remote_exchange;

	/**
	 * Create a signature...
	 *
	 */
	public static byte[] sign(PrivateKey pk, byte[] local_propose_bytes, byte[] remote_propose_bytes, byte[] epubkey) throws Exception {
		
		// Create the corpus
		byte[] corpus = new byte[remote_propose_bytes.length + local_propose_bytes.length + epubkey.length];
		ByteBuffer bb = ByteBuffer.allocate(corpus.length);
		bb.put(local_propose_bytes);
		bb.put(remote_propose_bytes);
		bb.put(epubkey);
		bb.flip();
		bb.get(corpus);

		// TODO: Do we need to support others?
		Signature sign = Signature.getInstance("SHA256withRSA");

		sign.initSign(pk);
		sign.update(corpus);
		return sign.sign();		
	}
	
	/**
	 * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
	 * @param w a 64 byte uncompressed EC point starting with <code>04</code>
	 * @return an <code>ECPublicKey</code> that the point represents 
	 */
	public static ECPublicKey generateP256PublicKeyFromUncompressedW(byte[] w) throws InvalidKeySpecException {
		if (w[0] != 0x04) {
			throw new InvalidKeySpecException("w is not an uncompressed key");
		}
		return generateP256PublicKeyFromFlatW(Arrays.copyOfRange(w, 1, w.length));
	}
	
	private static byte[] P256_HEAD = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE");
	//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE		// 36 characters in base64
	//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBnW6EfMLgy0/pPiL2xSwD3ygbmNI6eNtf/dsxPzpAUuoCTVs469GcJaWnV9WMkBcEfJcL9GpBihQ7qiR+n5uPw==
	
	/**
	 * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
	 * @param w a 64 byte uncompressed EC point consisting of just a 256-bit X and Y
	 * @return an <code>ECPublicKey</code> that the point represents 
	 */
	public static ECPublicKey generateP256PublicKeyFromFlatW(byte[] w) throws InvalidKeySpecException {
		byte[] encodedKey = new byte[P256_HEAD.length + w.length];
		System.arraycopy(P256_HEAD, 0, encodedKey, 0, P256_HEAD.length);
		System.arraycopy(w, 0, encodedKey, P256_HEAD.length, w.length);
		KeyFactory eckf;
		try {
			eckf = KeyFactory.getInstance("EC");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("EC key factory not present in runtime");
		}
		X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);
		return (ECPublicKey) eckf.generatePublic(ecpks);
	}
	
	public static KeyPair createECKeypair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(256, random);
        KeyPair pair = keyGen.generateKeyPair();

        return pair;
	}
	
	public static byte[] getECPublicKey(KeyPair kp) {
        // Get bytes for pub so we can send...
        byte[] pubk = kp.getPublic().getEncoded();
        String pubkeyenc = Base64.getEncoder().encodeToString(pubk);

        // Try extracting what we need to go into the packet...
		byte[] encodedKey = new byte[65];
		encodedKey[0] = 4;
		System.arraycopy(pubk, pubk.length - 64, encodedKey, 1, 64);
		return encodedKey;
	}
	
	private static void showHexData(byte[] d) {
		int o = 0;
		while(true) {
			String l = "";
			for(int i=0;i<Math.min(16, d.length - o); i++) {
				String ch = "00" + Integer.toString(((int)d[o+i]) & 0xff, 16);
				ch = ch.substring(ch.length() - 2, ch.length());
				l += " " + ch;
			}
			System.out.println(" " + l);
			o+=16;
			if (o>=d.length) break;
		}
	}

	public static String toHexString(byte[] d) {
		String o = "";
		for(int i=0;i<d.length;i++) {
			String ch = "00" + Integer.toString(((int)d[i]) & 0xff, 16);
			ch = ch.substring(ch.length() - 2, ch.length());
			o=o+ch;
		}
		return o;
	}
	
	public static byte[] fromHexString(String d) {
		byte[] o = new byte[d.length() / 2];
		for(int i=0;i<o.length;i++) {
			o[i] = (byte)Integer.parseInt(d.substring(i*2, i*2 + 2), 16);
		}
		return o;
	}
	
}