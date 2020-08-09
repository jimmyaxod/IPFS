package net.axod.crypto.secio;

import net.axod.pb.*;
import net.axod.util.*;

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

import org.bouncycastle.jce.provider.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;

/**
 * A Secio session handles SECIO
 * https://github.com/libp2p/go-libp2p-secio
 *
 *
 * Example usage:
 *		SecioSession secio = new SecioSession();
 * 		LinkedList in_packets = secio.process(in, out, mykeys);
 *		secio.write(something)
 *
 * TODO: Support more exchange, ciphers, hashers
 * TODO: If we support multiple exchange,ciphers,hashers decide which to use based
 *       on their list as well.
 * TODO: Support pubkey types
 *
 */
public class SecioSession {
    private static Logger logger = Logger.getLogger("net.axod.crypto.secio");

    // Are we outgoing, or incoming?
    private boolean is_outgoing = true;
    
	private boolean we_are_primary = true;

	// The EC keys
	private KeyPair ec_keys = null;

	// Final secio handshake verifying our nonces
	private boolean got_enc_nonce = false;
	private boolean sent_enc_nonce = false;

	private SecioProtos.Propose local_propose = null;
	private SecioProtos.Propose remote_propose = null;
	private SecioProtos.Exchange local_exchange = null;
	private SecioProtos.Exchange remote_exchange = null;

	private Mac incoming_HMAC;
	private Mac outgoing_HMAC;
	
	private Cipher incoming_cipher;
	private Cipher outgoing_cipher;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 *
	 * Create a new session
	 */
	public SecioSession() {
	
	}

	/**
	 * This decides who is in charge of the connection.
	 *
	 */
	private void decideOrder() {
		Timing.enter("Secio.decideOrder");
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
			
			if (hash1.equals(hash2)) {
				// ABORT! We connected to ourself??!	
			}
			
			we_are_primary = (hash1.compareTo(hash2) > 0);
			
		} catch(java.security.NoSuchAlgorithmException nae) {
			System.err.println("java.security.NoSuchAlgorithmException");
			System.exit(-1);	
		}
		Timing.leave("Secio.decideOrder");
	}

	/**
	 * Create a local exchange packet to send out.
	 * To do this, we need to know our PrivateKey so we can sign using it.
	 */
	private void createLocalExchange(PrivateKey privk) throws Exception {
		Timing.enter("Secio.createLocalExchange");
		// First we need to create EC keypair
		// Second we need to create a signature
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(256, random);
        ec_keys = keyGen.generateKeyPair();

		// Encode the pubkey as required...
        byte[] pubk = ec_keys.getPublic().getEncoded();

        // Try extracting what we need to go into the packet...
        // TODO: This may not be best way to do it...
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
		Timing.leave("Secio.createLocalExchange");
	}
	
	/**
	 * Create a local Propose packet to send out.
	 *
	 */
	private void createLocalPropose(byte[] publickey, String exchanges, String ciphers, String hashes) {
		Timing.enter("Secio.createLocalPropose");
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
		Timing.leave("Secio.createLocalPropose");
	}
	
	/**
	 * Check the signature of a received Exchange packet
	 *
	 */
	private boolean checkSignature() throws SecioException {
		Timing.enter("Secio.checkSignature");
		try {
			byte[] pubkey = remote_propose.getPubkey().toByteArray();
			PeerKeyProtos.PublicKey pka = PeerKeyProtos.PublicKey.parseFrom(pubkey);
			
			PeerKeyProtos.KeyType keytype = pka.getType();
			byte[] keybytes = pka.getData().toByteArray();

			PublicKey pk = null;
			Signature verify = null;

			if (keytype == PeerKeyProtos.KeyType.RSA) {
				pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keybytes));
				verify = Signature.getInstance("SHA256withRSA");
			} else if (keytype == PeerKeyProtos.KeyType.ECDSA) {
				pk = KeyFactory.getInstance("ECDSA").generatePublic(new X509EncodedKeySpec(keybytes));
				verify = Signature.getInstance("SHA256withECDSA");
			} else if (keytype == PeerKeyProtos.KeyType.Ed25519) {
				// Wrap public key in ASN.1 format so we can use X509EncodedKeySpec to read it
				SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), keybytes);
				X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyInfo.getEncoded());
				pk = KeyFactory.getInstance("Ed25519").generatePublic(x509KeySpec);
				verify = Signature.getInstance("Ed25519");
			} else {
				// TODO: Support any other keytypes...
				System.out.println("NEWKEYTYPE " + keytype);
				throw (new SecioException("Unsupported key " + keytype));
			}

			verify.initVerify(pk);
			verify.update(remote_propose.toByteArray());
			verify.update(local_propose.toByteArray());
			verify.update(remote_exchange.getEpubkey().toByteArray());
			return verify.verify(remote_exchange.getSignature().toByteArray());
		} catch(SecioException se) {
			throw(se);
		} catch(Exception e) {
			throw(new SecioException("Error checking signature " + e));
		} finally {
			Timing.leave("Secio.checkSignature");
		}
	}

	/**
	 * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
	 * @param w a 64 byte uncompressed EC point starting with <code>04</code>
	 * @return an <code>ECPublicKey</code> that the point represents 
	 */
	private static ECPublicKey generateP256PublicKeyFromUncompressedW(byte[] w) throws InvalidKeySpecException {
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
	private static ECPublicKey generateP256PublicKeyFromFlatW(byte[] w) throws InvalidKeySpecException {
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
	private void initCiphersMacs() throws Exception {
		Timing.enter("secio.initCiphersMacs");

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

		int secret_size = 32;
							// For key256, it's 32 bytes
							// For key384, it's 48 bytes
							// For key521, it's 66 bytes
							
							// For P-256, the shared secret should be 32 bytes...
		
		byte[] ss = new byte[secret_size];
		System.arraycopy(ass, 1, ss, 0, secret_size);		// Try the first 32 bytes for now...
															// NB ignore the first byte which is
															// just 04 signifying uncompressed key
															
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
		logger.fine("Secio: Have initialized HMAC and ciphers");
		Timing.leave("secio.initCiphersMacs");
	}

	/**
	 * Write some data out using the cipher and mac
	 *
	 */
	public void write(ByteBuffer out, ByteBuffer data) throws SecioException {
		if (!sent_enc_nonce) throw new SecioException("We haven't handshaked yet. Please wait");
		data.flip();
		byte[] d = new byte[data.remaining()];
		data.get(d);
		write(out, d);
	}

	/**
	 * Write some data out using the cipher and mac
	 *
	 */
	public void write(ByteBuffer out, byte[] data) throws SecioException {
		if (!sent_enc_nonce) throw new SecioException("We haven't handshaked yet. Please wait");		
		if (data.length==0) return;
		Timing.enter("secio.write");
		byte[] enc_data = outgoing_cipher.update(data);
		byte[] mac_data = outgoing_HMAC.doFinal(enc_data);
		
		out.putInt(enc_data.length + mac_data.length);
		out.put(enc_data);
		out.put(mac_data);	
		Timing.leave("secio.write");
	}

	/**
	 * Process some incomming data on this session...
	 * In PROPOSE
	 * Out PROPOSE
	 * In EXCHANGE
	 * Out EXCHANGE
	 * In nonce
	 * Out nonce
	 *
	 * @param	in	Input buffer
	 * @param	out	Output buffer, for handshaking etc
	 *
	 * @returns	LinkedList of incoming packets
	 */
	public LinkedList process(ByteBuffer in, ByteBuffer out, KeyPair mykeys) throws SecioException {
		LinkedList inq = new LinkedList();
		while(in.position()>0) {
			in.flip();
			try {
				int len = in.getInt();		// Length is 32bit int
				if (len>8000000) {
					logger.warning("Got a packet of >8MB?");
					throw new SecioException("Packet of >8MB");
				}

				byte[] data = new byte[len];
				in.get(data);

				if (remote_propose == null) {							
					remote_propose = SecioProtos.Propose.parseFrom(data);
					logger.fine("Secio remote propose\n" + remote_propose + "\n");

					createLocalPropose(mykeys.getPublic().getEncoded(), "P-256", "AES-256", "SHA256");							
					logger.fine("Secio local propose\n" + local_propose);							

					byte[] odata = local_propose.toByteArray();
					out.putInt(odata.length);
					out.put(odata);
				} else if (remote_exchange == null) {
							//
							// Now we have done the Propose, lets decide the order, and then we can decide on exchange, ciphers, hashes etc
					decideOrder();

							// Now we're expecting an Exchange...
					remote_exchange = SecioProtos.Exchange.parseFrom(data);
					logger.fine("Secio remote exchange\n" + remote_exchange + "\n");

					if (!checkSignature()) {
						logger.warning("Secio signature did not validate!");
						throw new SecioException("Secio signature did not validate");
					}

					createLocalExchange(mykeys.getPrivate());							
					logger.fine("Secio local exchange\n" + local_exchange);

					byte[] odata = local_exchange.toByteArray();
					out.putInt(odata.length);
					out.put(odata);

					initCiphersMacs();
				} else {
					// General incoming data then...
					
					// First split off the mac, verify that's correct
					int maclen = incoming_HMAC.getMacLength();
        			byte[] mac = new byte[maclen];
        			System.arraycopy(data, data.length - mac.length, mac, 0, mac.length);        					
        			byte[] datanomac = new byte[data.length - mac.length];
        			System.arraycopy(data, 0, datanomac, 0, datanomac.length);
					byte[] sign = incoming_HMAC.doFinal(datanomac);
					boolean verifies = ByteUtil.toHexString(sign).equals(ByteUtil.toHexString(mac));
					if (!verifies) {
						logger.warning("Incorrect MAC!");
						throw new SecioException("Secio incorrect MAC");
					}							
        			byte[] plainText = incoming_cipher.update(datanomac);

					if (!got_enc_nonce) {
						// check it matches...
						if (!ByteUtil.toHexString(plainText).equals(ByteUtil.toHexString(local_propose.getRand().toByteArray()))) {
							logger.warning("The decrypted nonce does NOT match");
							throw new SecioException("Secio nonce does NOT match");
						}

						got_enc_nonce = true;
						
						// Now we will send our own...
						sent_enc_nonce = true;
						write(out, remote_propose.getRand().toByteArray());
						logger.fine("Sent our encrypted signed nonce");
					} else {
						// Add the message to our return list...
						inq.add(plainText);
					}
				}
			} catch(BufferUnderflowException bue) {
				// Not enough data...
				in.rewind();		// Undo this packet read
				in.compact();
				break;
			} catch(SecioException se) {
				throw(se);
			} catch(Exception e) {
				throw(new SecioException(e.toString()));
			}
			in.compact();
		}
		return inq;
	}

	/**
	 * Process some incomming data on this session...
	 * Out PROPOSE
	 * In PROPOSE
	 * Out EXCHANGE
	 * In EXCHANGE
	 * Out nonce
	 * In nonce
	 *
	 * @param	in	Input buffer
	 * @param	out	Output buffer, for handshaking etc
	 *
	 * @returns	LinkedList of incoming packets
	 */
	public LinkedList processServer(ByteBuffer in, ByteBuffer out, KeyPair mykeys) throws SecioException {
		if (local_propose==null) {
			createLocalPropose(mykeys.getPublic().getEncoded(), "P-256", "AES-256", "SHA256");							
			logger.fine("Secio local propose\n" + local_propose);							

			byte[] odata = local_propose.toByteArray();
			out.putInt(odata.length);
			out.put(odata);			
		}
		
		LinkedList inq = new LinkedList();
		while(in.position()>0) {
			in.flip();
			try {
				int len = in.getInt();		// Length is 32bit int
				if (len>8000000) {
					logger.warning("Got a packet of >8MB?");
					throw new SecioException("Packet of >8MB");
				}

				byte[] data = new byte[len];
				in.get(data);

				if (remote_propose == null) {							
					remote_propose = SecioProtos.Propose.parseFrom(data);
					logger.fine("Secio remote propose\n" + remote_propose + "\n");
							//
							// Now we have done the Propose, lets decide the order, and then we can decide on exchange, ciphers, hashes etc
					decideOrder();

					createLocalExchange(mykeys.getPrivate());							
					logger.fine("Secio local exchange\n" + local_exchange);

					byte[] odata = local_exchange.toByteArray();
					out.putInt(odata.length);
					out.put(odata);					
				} else if (remote_exchange == null) {

							// Now we're expecting an Exchange...
					remote_exchange = SecioProtos.Exchange.parseFrom(data);
					logger.fine("Secio remote exchange\n" + remote_exchange + "\n");

					if (!checkSignature()) {
						logger.warning("Secio signature did not validate!");
						throw new SecioException("Secio signature did not validate");
					}

					initCiphersMacs();

					sent_enc_nonce = true;
					write(out, remote_propose.getRand().toByteArray());
					logger.fine("Sent our encrypted signed nonce");
				} else {
					// General incoming data then...
					
					// First split off the mac, verify that's correct
					int maclen = incoming_HMAC.getMacLength();
        			byte[] mac = new byte[maclen];
        			System.arraycopy(data, data.length - mac.length, mac, 0, mac.length);        					
        			byte[] datanomac = new byte[data.length - mac.length];
        			System.arraycopy(data, 0, datanomac, 0, datanomac.length);
					byte[] sign = incoming_HMAC.doFinal(datanomac);
					boolean verifies = ByteUtil.toHexString(sign).equals(ByteUtil.toHexString(mac));
					if (!verifies) {
						logger.warning("Incorrect MAC!");
						throw new SecioException("Secio incorrect MAC");
					}							
        			byte[] plainText = incoming_cipher.update(datanomac);

					if (!got_enc_nonce) {
						// check it matches...
						if (!ByteUtil.toHexString(plainText).equals(ByteUtil.toHexString(local_propose.getRand().toByteArray()))) {
							logger.warning("The decrypted nonce does NOT match");
							throw new SecioException("Secio nonce does NOT match");
						}

						got_enc_nonce = true;
					} else {
						// Add the message to our return list...
						inq.add(plainText);
					}
				}             
			} catch(BufferUnderflowException bue) {
				// Not enough data...
				in.rewind();		// Undo this packet read
				in.compact();
				break;
			} catch(SecioException se) {
				throw(se);
			} catch(Exception e) {
				throw(new SecioException(e.toString()));
			}
			in.compact();
		}
		return inq;
	}
	
	/**
	 * Accessor method for local public key
	 *
	 */
	public byte[] getLocalPublicKey() throws SecioException {
		if (local_propose==null) throw (new SecioException("hasn't been worked out yet!"));
		return local_propose.getPubkey().toByteArray();
	}
	
	/**
	 * Accessor method for remote public key
	 *
	 */
	public byte[] getRemotePublicKey() throws SecioException {
		if (remote_propose==null) throw (new SecioException("hasn't been worked out yet!"));
		return remote_propose.getPubkey().toByteArray();
	}
	
	public boolean handshaked() {
		return (sent_enc_nonce && got_enc_nonce);	
	}
}