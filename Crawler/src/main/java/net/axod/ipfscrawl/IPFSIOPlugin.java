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
	
	// This handles a SECIO session
	SecioSession secio = new SecioSession();

	
	boolean got_enc_multistream = false;
	boolean using_yamux = false;
	
	boolean setup_stream_7 = false;
	
	// My RSA keys
	KeyPair mykeys = null;
	

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
		secio.write(out, data);
	}

	/**
	 * Main work method.
	 *
	 */
	public void work() {
		logger.fine("Work " + in);
		
		if (in.position()>0) {
			
			// ======== Multistream handshake ==================================
			if (!handshaked) {
				// We haven't performed the multistream handshake yet, so we should do that now.
				in.flip();
				
				// Try to read a complete packet. If we can't we abort.
				try {
					String l = Multistream.readMultistream(in);	
					logger.fine("Multistream handshake (" + l.trim() + ")");

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
				} catch(BufferUnderflowException bue) {
					in.rewind();	// Partial packet. We'll try and read again later...
				}
				in.compact();
			}

			// ======== SECIO layer ============================================
			if (handshaked) {
				in.flip();
				while(in.remaining()>0) {
					try {
						int len = in.getInt();		// Length is 32bit int
						if (len>8000000) {
							logger.warning("Got a packet of >8MB?");
							close();
							return;
						}
						byte[] data = new byte[len];
						in.get(data);
						
						if (secio.remote_propose == null) {							
							secio.remote_propose = SecioProtos.Propose.parseFrom(data);
							logger.fine("Secio remote propose\n" + secio.remote_propose + "\n");
	
							byte[] pubkey = secio.remote_propose.getPubkey().toByteArray();
							PeerKeyProtos.PublicKey pk = PeerKeyProtos.PublicKey.parseFrom(pubkey);
							logger.info("Secio remote peerID " + getPeerID(pubkey));

							secio.createLocalPropose(mykeys.getPublic().getEncoded(), "P-256", "AES-256", "SHA256");							
							logger.fine("Secio local propose\n" + secio.local_propose);							

							byte[] odata = secio.local_propose.toByteArray();
							out.putInt(odata.length);
							out.put(odata);
						} else if (secio.remote_exchange == null) {
							//
							// Now we have done the Propose, lets decide the order, and then we can decide on exchange, ciphers, hashes etc
							secio.decideOrder();

							// Now we're expecting an Exchange...
							secio.remote_exchange = SecioProtos.Exchange.parseFrom(data);
							logger.fine("Secio remote exchange\n" + secio.remote_exchange + "\n");

							if (!secio.checkSignature()) {
								logger.warning("Secio signature did not validate!");
								close();
								return;
							}

							secio.createLocalExchange(mykeys.getPrivate());							
							logger.fine("Secio local exchange\n" + secio.local_exchange);

							byte[] odata = secio.local_exchange.toByteArray();
							out.putInt(odata.length);
							out.put(odata);

							secio.initCiphersMacs();
						} else {
							
							// First split off the mac, verify that's correct
							int maclen = secio.incoming_HMAC.getMacLength();
        					byte[] mac = new byte[maclen];
        					System.arraycopy(data, data.length - mac.length, mac, 0, mac.length);        					
        					byte[] datanomac = new byte[data.length - mac.length];
        					System.arraycopy(data, 0, datanomac, 0, datanomac.length);
							byte[] sign = secio.incoming_HMAC.doFinal(datanomac);
							boolean verifies = ByteUtil.toHexString(sign).equals(ByteUtil.toHexString(mac));
							if (!verifies) {
								logger.warning("Incorrect MAC!");
								close();
								return;
							}							
        					byte[] plainText = secio.incoming_cipher.update(datanomac);

							if (!secio.got_enc_nonce) {
								// check it matches...
								if (!ByteUtil.toHexString(plainText).equals(ByteUtil.toHexString(secio.local_propose.getRand().toByteArray()))) {
									logger.warning("The decrypted nonce does NOT match");
									close();
									return;
								}

								// Now we will send our own...
								secio.write(out, secio.remote_propose.getRand().toByteArray());
								logger.fine("Sent our encrypted signed nonce");
								
								secio.got_enc_nonce = true;
							} else {
								System.out.println("-- RAW DATA --");
								showHexData(plainText);

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

												System.out.println("HEX " + ByteUtil.toHexString(idd));

												System.out.println("Pub " + ByteUtil.toHexString(secio.remote_propose.getPubkey().toByteArray()));
																								

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