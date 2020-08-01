package net.axod.ipfscrawl;

import net.axod.*;
import net.axod.io.*;
import net.axod.protocols.*;

import net.axod.util.*;

import com.google.protobuf.*;

import io.ipfs.multihash.*;

import java.net.*;
import java.nio.*;
import java.util.*;
import java.security.*;
import java.math.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.logging.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * This represents a connection to an IPFS node.
 *
 * We need to jump through several hoops before we can get to the interesting
 * bits.
 *
 *
 *
 */
public class IPFSIOPlugin extends IOPlugin {
    private static Logger logger = Logger.getLogger("net.axod.ipfscrawl");

    // Initial multistream handshake
	boolean handshaked = false;
	
	// Have we got propose / exchange messages yet?
	boolean got_propose = false;
	boolean got_exchange = false;

	// We store the incoming and outgoing propose / exchange packets
	SecioProtos.Propose local_propose = null;
	SecioProtos.Propose remote_propose = null;
	SecioProtos.Exchange local_exchange = null;
	SecioProtos.Exchange remote_exchange = null;

	boolean we_are_primary = false;
	
	Mac incoming_HMAC;
	Mac outgoing_HMAC;
	
	Cipher incoming_cipher;
	Cipher outgoing_cipher;
	
	boolean got_enc_nonce = false;
	
	boolean got_enc_multistream = false;
	boolean using_yamux = false;
	
	// My RSA keys
	KeyPair mykeys = null;
	
	// The EC keys
	KeyPair ec_keys = null;

	byte[] stretched_keys = null;
	
	/**
	 * Given a public key, we can get a Multihash which shows the PeerID in a
	 * more usable format.
	 *
	 */
	public Multihash getPeerID(byte[] pubkey) {
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

	/**
	 * Create a new plugin to handle a connection.
	 *
	 */
	public IPFSIOPlugin(Node n, InetSocketAddress isa) {
        in.order(ByteOrder.BIG_ENDIAN);
        out.order(ByteOrder.BIG_ENDIAN);

        // TODO: Allow reusing previous keys. These should be stored and reused.
        try {
        	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        	SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        	keyGen.initialize(2048, random);

        	mykeys = keyGen.generateKeyPair();

        } catch(Exception e) {
        	logger.warning("Can't generate keys!");	
        }
	}

	/**
	 * Does the plugin need to send anything
	 */
	public boolean wantsToWork() {
		return false;	
	}

	/**
	 * Write a multistream message, using varint framing.
	 *
	 */
	private void writeMultistream(String d) {
		byte[] data = d.getBytes();
		writeVarInt(data.length);
		out.put(data);
	}

	private void writeYamuxMultistreamEnc(String d, int m_stream, short m_flags) {
		ByteBuffer bbm = ByteBuffer.allocate(8192);
		byte[] da = d.getBytes();
		writeVarInt(bbm, da.length);
		bbm.put(da);
		bbm.flip();
		byte[] multi_data = new byte[bbm.remaining()];
		bbm.get(multi_data);

		ByteBuffer bbo = ByteBuffer.allocate(8192);
		bbo.put((byte)0);	// ver
		bbo.put((byte)0);	// data
		bbo.putShort(m_flags);
		bbo.putInt(m_stream);	// Stream ID
		bbo.putInt(multi_data.length);
		bbo.put(multi_data);
		writeEnc(bbo);		// Write it out...
		
	}
	
	private void writeMultistreamEnc(String d) {
		byte[] da = d.getBytes();
		ByteBuffer oo = ByteBuffer.allocate(8192);
		writeVarInt(oo, da.length);
		oo.put(da);
		oo.flip();
		byte[] data = new byte[oo.remaining()];
		oo.get(data);
		
		writeEnc(data);
	}
	
	private void writeEnc(ByteBuffer bb) {
		bb.flip();
		byte[] data = new byte[bb.remaining()];
		bb.get(data);
		System.out.println("WRITING ENCRYPTED...");
		showHexData(data);
		
		writeEnc(data);
	}
	
	// Write encrypted data...
	private void writeEnc(byte[] data) {		
		byte[] enc_data = outgoing_cipher.update(data);
		byte[] mac_data = outgoing_HMAC.doFinal(enc_data);
		
		out.putInt(enc_data.length + mac_data.length);
		out.put(enc_data);
		out.put(mac_data);	
	}
	
	/**
	 * Write a varint out
	 *
	 */
	private void writeVarInt(long v) {
		writeVarInt(out, v);	
	}
	private void writeVarInt(ByteBuffer oo, long v) {
		while(true) {
			byte d = (byte)(v & 0x7f);
			if (v>0x80) {
				d = (byte) (d | 0x80);	// Signal there's more to come...
				oo.put(d);
			} else {
				oo.put(d);
				break;
			}
			v = v >> 7;
		}
	}

	/**
	 * Read a varint
	 *
	 */
	private long readVarInt() throws BufferUnderflowException {
		return readVarInt(in);
	}
	private long readVarInt(ByteBuffer bb) throws BufferUnderflowException {
		long len = 0;
		int sh = 0;
		while(true) {
			int b = ((int)bb.get()) & 0xff;
			long v = (b & 0x7f);
			len = len | (v << sh);
			if ((b & 0x80)==0) break;
			sh+=7;
		}
		return len;			
	}
	
	/**
	 * Main work method.
	 *
	 */
	public void work() {
		logger.fine("Work " + in);
		
		if (in.position()>0) {
			if (!handshaked) {
				// We haven't performed the multistream handshake yet, so we should
				// do that now.
				in.flip();
				
				// Try to read a complete packet. If we can't we abort.
				
				try {
					int len = (int)readVarInt();
					byte[] data = new byte[len];
					in.get(data);
					String l = new String(data);
					logger.info("Multistream handshake (" + l.trim() + ")");

					// For now, we only support multistream/1.0.0
					if (l.equals("/multistream/1.0.0\n")) {
						// OK, as expected, lets reply and progress...
						writeMultistream("/multistream/1.0.0\n");						
						writeMultistream("/secio/1.0.0\n");
						
					// For now, we only support secio/1.0.0
					} else if (l.equals("/secio/1.0.0\n")) {
						// OK, need to move on to next stage now...
						handshaked = true;
					}
				} catch(Exception e) {
					logger.warning("Issue reading... " + e);
					in.rewind();	// Unread it all... We'll try again later...	
				}
				in.compact();
			}
			
			// Now lets do SECIO
			if (handshaked) {
				in.flip();
				while(in.remaining()>0) {
					try {
						int len = in.getInt();		// Length is 32bit int
						if (len>8000000) {
							logger.warning("Got a packet of >8MB?");
							break;
						}
						byte[] data = new byte[len];
						in.get(data);
						
						if (!got_propose) {							
							remote_propose = SecioProtos.Propose.parseFrom(data);
	
							logger.info("Secio remote propose\n" + remote_propose + "\n");
	
							byte[] pubkey = remote_propose.getPubkey().toByteArray();
							PeerKeyProtos.PublicKey pk = PeerKeyProtos.PublicKey.parseFrom(pubkey);
							logger.info("Secio remote peerID " + getPeerID(pubkey));

							// Create our own PROPOSE
							byte[] orand = new byte[16];
							for(int i=0;i<orand.length;i++) {
								orand[i] = (byte) (Math.random() * 256);	
							}

        					PeerKeyProtos.PublicKey mpk = PeerKeyProtos.PublicKey.newBuilder()
        												 .setType(PeerKeyProtos.KeyType.RSA)
        												 .setData(ByteString.copyFrom(mykeys.getPublic().getEncoded()))
        												 .build();
        					
        					logger.info("Secio local peerID " + getPeerID(mykeys.getPublic().getEncoded()));

							byte[] opubkey = mpk.toByteArray();
							String oexchanges = remote_propose.getExchanges();
							String ociphers = remote_propose.getCiphers();
							String ohashes = remote_propose.getHashes();

							// Lets create our own...
							local_propose = SecioProtos.Propose.newBuilder()
													  .setRand(ByteString.copyFrom(orand))
													  .setPubkey(ByteString.copyFrom(opubkey))
													  .setExchanges("P-256")	//oexchanges)
													  .setCiphers("AES-256")	//ociphers)
													  .setHashes("SHA256")		//ohashes)
													  .build();
							
							byte[] odata = local_propose.toByteArray();

							logger.info("Secio local propose\n" + local_propose);							
							out.putInt(odata.length);
							out.put(odata);

							got_propose = true;
						} else if (!got_exchange) {
							//
							// Now we have done the Propose, lets decide the order, and then we can decide on exchange, ciphers, hashes etc
							
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
							
							logger.info("oh1 = " + SecioHelper.toHexString(oh1) + " " + h1);
							logger.info("oh2 = " + SecioHelper.toHexString(oh2) + " " + h2);
							
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
							
							logger.info("we_are_primary = " + we_are_primary);
							
							// Now we're expecting an Exchange...
							remote_exchange = SecioProtos.Exchange.parseFrom(data);

							logger.info("Secio remote exchange\n" + remote_exchange + "\n");

							// TODO: We should do all the check to see who is who, and
							// then decide which cyphers win etc.
							//
							// For now, we'll just assume p-256

							try {
								byte[] pubkey = remote_propose.getPubkey().toByteArray();
								PeerKeyProtos.PublicKey pk = PeerKeyProtos.PublicKey.parseFrom(pubkey);
								
								byte[] keybytes = pk.getData().toByteArray();		
								PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keybytes));
								System.out.println("Remote publickey " + publicKey);
						
								boolean verified = SecioHelper.checkSignature(publicKey, local_propose.toByteArray(), remote_propose.toByteArray(), remote_exchange);

								System.out.println("Secio remote checking signature... [" + (verified?"correct":"incorrect") + "]");
								if (!verified) {
									close();
									return;
								}
							} catch(Exception ve) {
								logger.warning("Can't verify " + ve);	
								ve.printStackTrace();
								close();
								return;
							}

							// First we need to create EC keypair
							// Second we need to create a signature
							ec_keys = SecioHelper.createECKeypair();
							
							// Encode the pubkey as required...
							byte[] ec_pubkey = SecioHelper.getECPublicKey(ec_keys);
							
							// Now create the signature...
							byte[] signature = SecioHelper.sign(mykeys.getPrivate(), local_propose.toByteArray(), remote_propose.toByteArray(), ec_pubkey);
							
							// TODO: Send out our exchange...
							local_exchange = SecioProtos.Exchange.newBuilder()
											.setEpubkey(ByteString.copyFrom(ec_pubkey))
											.setSignature(ByteString.copyFrom(signature))
											.build();

							byte[] odata = local_exchange.toByteArray();
	
							logger.info("Secio local exchange\n" + local_exchange);							
							out.putInt(odata.length);
							out.put(odata);
							
							got_exchange = true;
							

							
							BigInteger ec_priv = ((ECPrivateKey)ec_keys.getPrivate()).getS();

							System.out.println("Our EC private key\n" + ec_priv);
							
							ECPublicKey their_pub = SecioHelper.generateP256PublicKeyFromUncompressedW(remote_exchange.getEpubkey().toByteArray());
							
							System.out.println("Their EC Public key\n" + their_pub);

							// Next we need to perform (their_pub * ec_priv) which will create a new ECPoint

							org.bouncycastle.asn1.x9.X9ECParameters ecp = org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256r1");
							org.bouncycastle.math.ec.ECCurve curve = ecp.getCurve();
							org.bouncycastle.math.ec.ECPoint p = curve.decodePoint(remote_exchange.getEpubkey().toByteArray());
							
							System.out.println("ECPoint p = " + p.getXCoord().toBigInteger() + " " + p.getYCoord().toBigInteger());
							
							org.bouncycastle.math.ec.ECPoint q = p.multiply(ec_priv);
							byte[] ass = q.getEncoded(false);

							System.out.println("Created shared secret");
							showHexData(ass);
							
							byte[] ss = new byte[32];
							System.arraycopy(ass, 1, ss, 0, 32);		// Try the first 32 bytes for now...

							// For P-256, the shared secret should be 32 bytes...
/*
  PubKey256Length* = 65
  PubKey384Length* = 97
  PubKey521Length* = 133
  SecKey256Length* = 32
  SecKey384Length* = 48
  SecKey521Length* = 66
  Sig256Length* = 64
  Sig384Length* = 96
  Sig521Length* = 132
  Secret256Length* = SecKey256Length
  Secret384Length* = SecKey384Length
  Secret521Length* = SecKey521Length
*/
							
							// TODO: Key stretching

							stretched_keys = SecioHelper.stretchKeys(ss, "AES-256", "SHA256");
							
							System.out.println("== Stretched Keys ==");
							showHexData(stretched_keys);

							// Now, we should be able to use this to proceed...
							
							// stretched_keys has 2 sets of keys in...
							// 
							byte[][] keys = SecioHelper.splitStretchedKeys(stretched_keys, "AES-256", "SHA256");

							byte[] liv;
							byte[] lkey;
							byte[] lmac;
							byte[] riv;
							byte[] rkey;
							byte[] rmac;

							if (we_are_primary) {
								liv = keys[0];
								lkey = keys[1];
								lmac = keys[2];
								riv = keys[3];
								rkey = keys[4];
								rmac = keys[5];
							} else {
								riv = keys[0];
								rkey = keys[1];
								rmac = keys[2];
								liv = keys[3];
								lkey = keys[4];
								lmac = keys[5];
							}

							incoming_HMAC = Mac.getInstance("HmacSHA256");
							incoming_HMAC.init(new SecretKeySpec(rmac, "HmacSHA256"));
							outgoing_HMAC = Mac.getInstance("HmacSHA256");
							outgoing_HMAC.init(new SecretKeySpec(lmac, "HmacSHA256"));

        					incoming_cipher = Cipher.getInstance("AES/CTR/NoPadding");
        					incoming_cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rkey, "AES"), new IvParameterSpec(riv));
        					outgoing_cipher = Cipher.getInstance("AES/CTR/NoPadding");
        					outgoing_cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(lkey, "AES"), new IvParameterSpec(liv));
        					logger.info("Have initialized HMAC and ciphers");
        					
						} else {
							System.out.println("Secio DATA " + data.length);
							showHexData(data);

							// First split off the mac. For now assume 32 bytes
        					byte[] mac = new byte[32];
        					System.arraycopy(data, data.length - mac.length, mac, 0, mac.length);        					
        					byte[] datanomac = new byte[data.length - 32];
        					System.arraycopy(data, 0, datanomac, 0, datanomac.length);

							byte[] sign = incoming_HMAC.doFinal(datanomac);
							boolean verifies = SecioHelper.toHexString(sign).equals(SecioHelper.toHexString(mac));
							if (!verifies) {
								logger.warning("Incorrect MAC!");
							}
							
							System.out.println("\n==== Decryption ====\n");
        					byte[] plainText = incoming_cipher.update(datanomac);

        					System.out.println("RAW DATA " + (verifies?"Verifies":"DOES NOT VERIFY"));
							showHexData(plainText);
							
							if (!got_enc_nonce) {
								// check it matches...
								if (SecioHelper.toHexString(plainText).equals(SecioHelper.toHexString(local_propose.getRand().toByteArray()))) {
									logger.info("The decrypted nonce matches");	
								}

								// Now we will send our own...
								
								byte[] enc_data = outgoing_cipher.update(remote_propose.getRand().toByteArray());
								byte[] mac_data = outgoing_HMAC.doFinal(enc_data);
								
								out.putInt(enc_data.length + mac_data.length);
								out.put(enc_data);
								out.put(mac_data);

								logger.info("Sent our encrypted signed nonce");
								
								got_enc_nonce = true;
							} else {
								
								if (!using_yamux) {
									ByteBuffer inbuff = ByteBuffer.wrap(plainText);
	
									int mlen = (int)readVarInt(inbuff);
									byte[] mdata = new byte[mlen];
									inbuff.get(mdata);
									String l = new String(mdata);
									logger.info("Multistream handshake (" + l.trim() + ")");
									
									if (l.equals("/multistream/1.0.0\n")) {
										// Send it back...
										writeMultistreamEnc("/multistream/1.0.0\n");						
										writeMultistreamEnc("/yamux/1.0.0\n");						
									} else if (l.equals("/yamux/1.0.0\n")) {
										using_yamux = true;	
									}
								} else {
									System.out.println("Decoding yamux");
									ByteBuffer inbuff = ByteBuffer.wrap(plainText);
									byte m_ver = inbuff.get();
									byte m_type = inbuff.get();
									short m_flags = inbuff.getShort();
									int m_stream = inbuff.getInt();
									int m_length = inbuff.getInt();

									System.out.println("yamux ver=" + m_ver + " type=" + m_type + " flags=" + m_flags + " id=" + m_stream + " len=" + m_length);

									if (m_type==0) { // DATA
										while(inbuff.remaining()>0) {
											int mlen = (int)readVarInt(inbuff);
											byte[] mdata = new byte[mlen];
											inbuff.get(mdata);
											String l = new String(mdata);
											logger.info("Yamux(" + m_stream + ") Multistream handshake (" + l.trim() + ")");
											
											if (l.equals("/multistream/1.0.0\n")) {
												writeYamuxMultistreamEnc("/multistream/1.0.0\n", m_stream, (short)2);
												writeYamuxMultistreamEnc("/ipfs/id/1.0.0\n", m_stream, (short)0);
											}
										}
									} else if (m_type==1) {	// Window update
										
									} else if (m_type==2) { // ping
										
									} else if (m_type==3) { // go away
										
									}
									
								}
//										  VER 00
//										  TYPE 01
//										  FLAGS 00 01
//										  STREAMID 00 00 00 02
//									      LENGTH 00 fc 00 00

//  									  VER 00
//										  TYPE 00
//										  FLAGS 00 00
//										  STREAMID 00 00 00 02
//										  LENGTH 00 00 00 24
//
//										  13 / 2f 6d 75 6c 74 69 73 74 72 65 61 6d 2f 31 2e 30 2e 30 0a
//												"/multistream/1.0.0"
//  									  0f / 2f 69 70 66 73 2f 69 64 2f 31 2e 30 2e 30 0a
//												"/ipfs/id/1.0.0"

										
								
								
							}
						}
					} catch(BufferUnderflowException bue) {
						// Don't have the data yet...
						in.rewind();	// 'Unread' any partial packet
						break;
					} catch(Exception e) {
						logger.warning("Exception " + e);
						e.printStackTrace();
						close();
						break;
					}
					// Get rid of this packet, and move on to the next...
					in.compact();
					in.flip();
				}
				in.compact();
			}
		}
	}
	
/*
RAW DATA Verifies
  5a 6e ca e5 78 08 5f 82 26 24 bd cb 50 84 c3 1d
  9f 42 fb 34
	
RAW DATA Verifies
  64 02 37 3e ff ff e6 82 56 09 4c 51 73 f6 16 b2
  0e be 9a 59
*/
	public void closing() {
		logger.info("Connection closing...");
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
	
}