package net.axod.crypto;

import net.axod.*;

import com.google.protobuf.*;

import io.ipfs.multihash.*;

import java.math.*;
import java.nio.*;
import java.util.*;
import java.util.logging.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;


/**
 * A Secio session handles SECIO
 *
 *
 *
 */
public class SecioSession {
    private static Logger logger = Logger.getLogger("net.axod.crypto");

	public boolean we_are_primary = true;
	
	public SecioProtos.Propose local_propose = null;
	public SecioProtos.Propose remote_propose = null;
	public SecioProtos.Exchange local_exchange = null;
	public SecioProtos.Exchange remote_exchange = null;

	public Mac incoming_HMAC;
	public Mac outgoing_HMAC;
	
	public Cipher incoming_cipher;
	public Cipher outgoing_cipher;

	// The EC keys
	public KeyPair ec_keys = null;

	// Final secio handshake verifying our nonces
	public boolean got_enc_nonce = false;
	
	/**
	 *
	 * Create a new session
	 */
	public SecioSession() {
		
	}
	
	/**
	 * This decides who is in charge.
	 *
	 */
	public void decideOrder() {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(remote_propose.getPubkey().toByteArray());
			md.update(local_propose.getRand().toByteArray());
			byte[] oh1 = md.digest();
			Multihash h1 = new Multihash(Multihash.Type.sha2_256, oh1);
			
			md.reset();
			md.update(local_propose.getPubkey().toByteArray());
			md.update(remote_propose.getRand().toByteArray());
			byte[] oh2 = md.digest();
			Multihash h2 = new Multihash(Multihash.Type.sha2_256, oh2);
			
			String hash1 = h1.toString();
			String hash2 = h2.toString();
			
			for(int i=0;i<hash1.length();i++) {
				char c1 = hash1.charAt(i);
				char c2 = hash2.charAt(i);
				if (c1==c2) {
					// Carry on...
				} else if (c1<c2) {
					we_are_primary = false;
					break;
				} else if (c1>c2) {
					we_are_primary = true;
					break;
				}
			}	
		} catch(java.security.NoSuchAlgorithmException nae) {
			System.err.println("java.security.NoSuchAlgorithmException");
			System.exit(-1);	
		}
	}
	
	public void createLocalExchange(PrivateKey privk) throws Exception {
		// First we need to create EC keypair
		// Second we need to create a signature
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(256, random);
        ec_keys = keyGen.generateKeyPair();
		
		// Encode the pubkey as required...
        byte[] pubk = ec_keys.getPublic().getEncoded();

        // Try extracting what we need to go into the packet...
		byte[] ec_pubkey = new byte[65];
		ec_pubkey[0] = 4;
		System.arraycopy(pubk, pubk.length - 64, ec_pubkey, 1, 64);
		
		// Now create the signature...

		// TODO: Do we need to support others?
		Signature sign = Signature.getInstance("SHA256withRSA");

		sign.initSign(privk);
		sign.update(local_propose.toByteArray());
		sign.update(remote_propose.toByteArray());
		sign.update(ec_pubkey);
		
		byte[] signature = sign.sign();
		
		local_exchange = SecioProtos.Exchange.newBuilder()
						.setEpubkey(ByteString.copyFrom(ec_pubkey))
						.setSignature(ByteString.copyFrom(signature))
						.build();		
	}
	
	public void createLocalPropose(byte[] publickey, String exchanges, String ciphers, String hashes) {
		// Create our own random nonce...
		byte[] orand = new byte[16];
		for(int i=0;i<orand.length;i++) {
			orand[i] = (byte) (Math.random() * 256);	
		}

		PeerKeyProtos.PublicKey mpk = PeerKeyProtos.PublicKey.newBuilder()
									 .setType(PeerKeyProtos.KeyType.RSA)
									 .setData(ByteString.copyFrom(publickey))
									 .build();

		byte[] opubkey = mpk.toByteArray();

		// Lets create our own...
		local_propose = SecioProtos.Propose.newBuilder()
								  .setRand(ByteString.copyFrom(orand))
								  .setPubkey(ByteString.copyFrom(opubkey))
								  .setExchanges(exchanges)
								  .setCiphers(ciphers)
								  .setHashes(hashes)
								  .build();
	}
	
	public boolean checkSignature() throws Exception {
		byte[] pubkey = remote_propose.getPubkey().toByteArray();
		PeerKeyProtos.PublicKey pka = PeerKeyProtos.PublicKey.parseFrom(pubkey);
		
		// TODO: Make sure it's an RSA key...
		
		byte[] keybytes = pka.getData().toByteArray();		
		PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keybytes));

		// TODO: Do we need to support others?
		Signature verify = Signature.getInstance("SHA256withRSA");
		verify.initVerify(pk);
		verify.update(remote_propose.toByteArray());
		verify.update(local_propose.toByteArray());
		verify.update(remote_exchange.getEpubkey().toByteArray());
		return verify.verify(remote_exchange.getSignature().toByteArray());		
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
	
	/**
	 * Initialize ciphers and macs
	 *
	 */
	public void initCiphersMacs() throws Exception {
		String cipher = "AES-256";
		String hasher = "SHA256";
		
		BigInteger ec_priv = ((ECPrivateKey)ec_keys.getPrivate()).getS();

		ECPublicKey their_pub = generateP256PublicKeyFromUncompressedW(remote_exchange.getEpubkey().toByteArray());

		// Next we need to perform (their_pub * ec_priv) which will create a new ECPoint

		org.bouncycastle.asn1.x9.X9ECParameters ecp = org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256r1");
		org.bouncycastle.math.ec.ECCurve curve = ecp.getCurve();
		org.bouncycastle.math.ec.ECPoint p = curve.decodePoint(remote_exchange.getEpubkey().toByteArray());
							
		org.bouncycastle.math.ec.ECPoint q = p.multiply(ec_priv);
		byte[] ass = q.getEncoded(false);

		byte[] ss = new byte[32];
		System.arraycopy(ass, 1, ss, 0, 32);		// Try the first 32 bytes for now...
							// For key256, it's 32 bytes
							// For key384, it's 48 bytes
							// For key521, it's 66 bytes
							
							// For P-256, the shared secret should be 32 bytes...

		//
		
		int iv_size = 16;
		int key_size = 16;		// AES-128 is 16, AES-256 is 32
		if (cipher.equals("AES-128")) key_size = 16;
		if (cipher.equals("AES-256")) key_size = 32;
		int mac_size = 20;

		byte[] seed = "key expansion".getBytes();
		
		byte[] stretched_keys = new byte[(iv_size + key_size + mac_size) * 2];

		// Need to strip off any leading 0s, because of stupid go.
		int soffset = 0;
		while(soffset<ss.length && ss[soffset]==0) soffset++;
		byte[] ss_z = new byte[ss.length - soffset];
		System.arraycopy(ss, soffset, ss_z, 0, ss_z.length);
		
		Mac sha_HMAC = Mac.getInstance("Hmac" + hasher);
		SecretKeySpec secret_key = new SecretKeySpec(ss_z, "Hmac" + hasher);
		sha_HMAC.init(secret_key);
		byte[] idig = sha_HMAC.doFinal(seed);
			
		// Now go through...
		int j = 0;
		while(j<stretched_keys.length) {
			sha_HMAC.init(secret_key);
			sha_HMAC.update(idig);
			byte[] idigb = sha_HMAC.doFinal(seed);

			// Write it out and continue...
			int todo = idigb.length;
			if (j + todo > stretched_keys.length) {
				todo = stretched_keys.length - j;	
			}
			System.arraycopy(idigb, 0, stretched_keys, j, todo);
			j+=todo;
			// Now update idig...
			sha_HMAC.init(secret_key);
			idig = sha_HMAC.doFinal(idig);
		}
		
		// stretched_keys has 2 sets of keys in...
		//
		
		int offset = 0;
		byte[] iv1 = new byte[iv_size];
		System.arraycopy(stretched_keys, offset, iv1, 0, iv_size);
		offset+=iv_size;
		byte[] key1 = new byte[key_size];
		System.arraycopy(stretched_keys, offset, key1, 0, key_size);
		offset+=key_size;
		byte[] mac1 = new byte[mac_size];
		System.arraycopy(stretched_keys, offset, mac1, 0, mac_size);
		offset+=mac_size;
		
		byte[] iv2 = new byte[iv_size];
		System.arraycopy(stretched_keys, offset, iv2, 0, iv_size);
		offset+=iv_size;
		byte[] key2 = new byte[key_size];
		System.arraycopy(stretched_keys, offset, key2, 0, key_size);
		offset+=key_size;
		byte[] mac2 = new byte[mac_size];
		System.arraycopy(stretched_keys, offset, mac2, 0, mac_size);
		offset+=mac_size;
		
		byte[] liv;
		byte[] lkey;
		byte[] lmac;
		byte[] riv;
		byte[] rkey;
		byte[] rmac;

		if (we_are_primary) {
			liv = iv1;
			lkey = key1;
			lmac = mac1;
			riv = iv2;
			rkey = key2;
			rmac = mac2;
		} else {
			riv = iv1;
			rkey = key1;
			rmac = mac1;
			liv = iv2;
			lkey = key2;
			lmac = mac2;
		}

		incoming_HMAC = Mac.getInstance("Hmac" + hasher);
		incoming_HMAC.init(new SecretKeySpec(rmac, "Hmac" + hasher));
		outgoing_HMAC = Mac.getInstance("Hmac" + hasher);
		outgoing_HMAC.init(new SecretKeySpec(lmac, "Hmac" + hasher));

		incoming_cipher = Cipher.getInstance("AES/CTR/NoPadding");
		incoming_cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rkey, "AES"), new IvParameterSpec(riv));
		outgoing_cipher = Cipher.getInstance("AES/CTR/NoPadding");
		outgoing_cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(lkey, "AES"), new IvParameterSpec(liv));
		logger.info("Have initialized HMAC and ciphers");
	}
	
	public void write(ByteBuffer out, ByteBuffer data) {
		data.flip();
		byte[] d = new byte[data.remaining()];
		data.get(d);
		write(out, d);
	}
	
	// Write encrypted data...
	public void write(ByteBuffer out, byte[] data) {		
		byte[] enc_data = outgoing_cipher.update(data);
		byte[] mac_data = outgoing_HMAC.doFinal(enc_data);
		
		out.putInt(enc_data.length + mac_data.length);
		out.put(enc_data);
		out.put(mac_data);	
	}

}