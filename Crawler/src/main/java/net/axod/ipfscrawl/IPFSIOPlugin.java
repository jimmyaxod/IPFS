package net.axod.ipfscrawl;

import net.axod.*;
import net.axod.io.*;
import net.axod.protocols.*;
import net.axod.crypto.*;

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

	// This handles a SECIO session
	SecioSession secio = new SecioSession();
	
	Mac incoming_HMAC;
	Mac outgoing_HMAC;
	
	Cipher incoming_cipher;
	Cipher outgoing_cipher;
	
	boolean got_enc_nonce = false;
	
	boolean got_enc_multistream = false;
	boolean using_yamux = false;
	
	boolean setup_stream_7 = false;
	
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

	private void writeYamuxMultistreamEnc(String d, int m_stream, short m_flags) {
		ByteBuffer bbm = ByteBuffer.allocate(8192);
		Multistream.writeMultistream(bbm, d);		
		bbm.flip();
		byte[] multi_data = new byte[bbm.remaining()];
		bbm.get(multi_data);

		ByteBuffer bbo = ByteBuffer.allocate(8192);
		Yamux.writeYamux(bbo, multi_data, m_stream, m_flags);
		writeEnc(bbo);		// Write it out...
	}

	private void writeEnc(ByteBuffer bb) {
		bb.flip();
		byte[] data = new byte[bb.remaining()];
		bb.get(data);
//		System.out.println("WRITING ENCRYPTED...");
//		showHexData(data);
		
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
					String l = Multistream.readMultistream(in);					
					logger.info("Multistream handshake (" + l.trim() + ")");

					// For now, we only support multistream/1.0.0
					if (l.equals("/multistream/1.0.0\n")) {
						// OK, as expected, lets reply and progress...
						Multistream.writeMultistream(out, "/multistream/1.0.0\n");						
						Multistream.writeMultistream(out, "/secio/1.0.0\n");
						
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
							secio.remote_propose = SecioProtos.Propose.parseFrom(data);
							logger.info("Secio remote propose\n" + secio.remote_propose + "\n");
	
							byte[] pubkey = secio.remote_propose.getPubkey().toByteArray();
							PeerKeyProtos.PublicKey pk = PeerKeyProtos.PublicKey.parseFrom(pubkey);
							logger.info("Secio remote peerID " + getPeerID(pubkey));

							secio.createLocalPropose(mykeys.getPublic().getEncoded(), "P-256", "AES-256", "SHA256");							
							byte[] odata = secio.local_propose.toByteArray();

							logger.info("Secio local propose\n" + secio.local_propose);							
							out.putInt(odata.length);
							out.put(odata);

							got_propose = true;
						} else if (!got_exchange) {
							//
							// Now we have done the Propose, lets decide the order, and then we can decide on exchange, ciphers, hashes etc
							
							secio.decideOrder();

							logger.info("we_are_primary = " + secio.we_are_primary);
							
							// Now we're expecting an Exchange...
							secio.remote_exchange = SecioProtos.Exchange.parseFrom(data);

							logger.info("Secio remote exchange\n" + secio.remote_exchange + "\n");

							try {
								boolean verified = secio.checkSignature();
								
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
							byte[] signature = SecioHelper.sign(mykeys.getPrivate(), secio.local_propose.toByteArray(), secio.remote_propose.toByteArray(), ec_pubkey);
							
							// TODO: Send out our exchange...
							secio.local_exchange = SecioProtos.Exchange.newBuilder()
											.setEpubkey(ByteString.copyFrom(ec_pubkey))
											.setSignature(ByteString.copyFrom(signature))
											.build();

							byte[] odata = secio.local_exchange.toByteArray();
	
							logger.info("Secio local exchange\n" + secio.local_exchange);							
							out.putInt(odata.length);
							out.put(odata);
							
							got_exchange = true;
							
							
							BigInteger ec_priv = ((ECPrivateKey)ec_keys.getPrivate()).getS();

							System.out.println("Our EC private key\n" + ec_priv);
							
							ECPublicKey their_pub = SecioHelper.generateP256PublicKeyFromUncompressedW(secio.remote_exchange.getEpubkey().toByteArray());
							
							System.out.println("Their EC Public key\n" + their_pub);

							// Next we need to perform (their_pub * ec_priv) which will create a new ECPoint

							org.bouncycastle.asn1.x9.X9ECParameters ecp = org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256r1");
							org.bouncycastle.math.ec.ECCurve curve = ecp.getCurve();
							org.bouncycastle.math.ec.ECPoint p = curve.decodePoint(secio.remote_exchange.getEpubkey().toByteArray());
							
							org.bouncycastle.math.ec.ECPoint q = p.multiply(ec_priv);
							byte[] ass = q.getEncoded(false);

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

							if (secio.we_are_primary) {
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
								if (SecioHelper.toHexString(plainText).equals(SecioHelper.toHexString(secio.local_propose.getRand().toByteArray()))) {
									logger.info("The decrypted nonce matches");	
								}

								// Now we will send our own...
								
								byte[] enc_data = outgoing_cipher.update(secio.remote_propose.getRand().toByteArray());
								byte[] mac_data = outgoing_HMAC.doFinal(enc_data);
								
								out.putInt(enc_data.length + mac_data.length);
								out.put(enc_data);
								out.put(mac_data);

								logger.info("Sent our encrypted signed nonce");
								
								got_enc_nonce = true;
							} else {

								if (!using_yamux) {
									ByteBuffer inbuff = ByteBuffer.wrap(plainText);
									while(inbuff.remaining()>0) {
										String l = Multistream.readMultistream(inbuff);
										logger.info("Multistream handshake (" + l.trim() + ")");
										
										if (l.equals("/multistream/1.0.0\n")) {
											ByteBuffer bb = ByteBuffer.allocate(8192);
											Multistream.writeMultistream(bb, "/multistream/1.0.0\n");
											Multistream.writeMultistream(bb, "/yamux/1.0.0\n");
											writeEnc(bb);
										} else if (l.equals("/yamux/1.0.0\n")) {
											using_yamux = true;
											
											// Try starting one...
											writeYamuxMultistreamEnc("/multistream/1.0.0\n", 7, (short)1);
											writeYamuxMultistreamEnc("/ipfs/id/1.0.0\n", 7, (short)0);
											
											
											break;
										}
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
										if (m_stream==7) {
											if (!setup_stream_7) {
											
												while(inbuff.remaining()>0) {
													String l = Multistream.readMultistream(inbuff);											
													logger.info("Yamux(" + m_stream + ") Multistream handshake (" + l.trim() + ")");
													if (l.equals("/ipfs/id/1.0.0\n")) {
														setup_stream_7 = true;	
													}
												}
											}
											if (inbuff.remaining()>0) {
												
												//int ll = inbuff.getShort();
												// WHY?
												
												//System.out.println("CHECK " + ll + " " + inbuff.remaining());
												
												byte[] idd = new byte[inbuff.remaining()];
												inbuff.get(idd);
												
												System.out.println("HEX DATA");
												showHexData(idd);

												System.out.println("HEX " + SecioHelper.toHexString(idd));

												System.out.println("Pub " + SecioHelper.toHexString(secio.remote_propose.getPubkey().toByteArray()));
																								

												//for(int i=1;i<32;i++) {
												//	byte[] nn = new byte[idd.length - i];
												//	System.arraycopy(idd, i, nn, 0, nn.length);
												//	System.out.println("Attempt " + i);
													try {
														IPFSProtos.Identify id = IPFSProtos.Identify.parseFrom(idd);
														System.out.println("=== THEIR ID ===\n" + id);
													} catch(Exception e) {
														System.out.println("Can't make it into an ID packet");
														e.printStackTrace();
													}
												//}
											}
										} else {
										
											while(inbuff.remaining()>0) {
												String l = Multistream.readMultistream(inbuff);											
												logger.info("Yamux(" + m_stream + ") Multistream handshake (" + l.trim() + ")");
												
												if (l.equals("/multistream/1.0.0\n")) {
	
													writeYamuxMultistreamEnc("/multistream/1.0.0\n", m_stream, (short)2);
													writeYamuxMultistreamEnc("/ipfs/id/1.0.0\n", m_stream, (short)0);
	
												} else if (l.equals("/ipfs/id/1.0.0\n")) {
													System.out.println("TODO: Send our ID info...");
													IPFSProtos.Identify id = IPFSProtos.Identify.newBuilder()
																 .setProtocolVersion("ipfs/0.1.0")
																 .setAgentVersion("mindYourOwnBusiness/0.0.1")
																 .setPublicKey(ByteString.copyFrom(secio.local_propose.getPubkey().toByteArray()))
																 .addListenAddrs(ByteString.copyFromUtf8("/ip4/127.0.0.1/tcp/4001/p2p/QmUXRZsrivZbvUcVPG1HPay5rnwhwoFAPpi1baLr11v4nf"))
																 .setObservedAddr(ByteString.copyFromUtf8("/ip4/127.0.0.1/tcp/4001/p2p/QmUXRZsrivZbvUcVPG1HPay5rnwhwoFAPpi1baLr11v4nf"))
																 .addProtocols("")
																 .build();
													System.out.println("Our ID " + id);
	
													byte[] multi_data = id.toByteArray();
													ByteBuffer bbo = ByteBuffer.allocate(8192);
													Yamux.writeYamux(bbo, multi_data, m_stream, (short)0);
													//writeEnc(bbo);		// Write it out...
												}
											}
										}
									} else if (m_type==1) {	// Window update
										
									} else if (m_type==2) { // ping
										
									} else if (m_type==3) { // go away
										
									}
									
								}
								
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