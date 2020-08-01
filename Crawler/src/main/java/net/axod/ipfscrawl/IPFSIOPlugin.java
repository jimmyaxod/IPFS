package net.axod.ipfscrawl;

import net.axod.*;
import net.axod.io.*;
import net.axod.protocols.*;
import net.axod.crypto.*;

import net.axod.util.*;

import com.google.protobuf.*;
import com.google.protobuf.util.*;

import io.ipfs.multihash.*;
import io.ipfs.multiaddr.*;

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

    String host = null;
    
    // Initial multistream handshake
	boolean handshaked = false;
	
	// This handles a SECIO session
	SecioSession secio = new SecioSession();

	
	boolean got_enc_multistream = false;
	boolean using_yamux = false;

	boolean setup_stream_6 = false;
	
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
        
        host = (String)n.properties.get("host");
        Crawl.registerConnection(host);
        
        
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

	private long lastPingTime = 0;
	private long PERIOD_PING = 10*1000;

	private long lastQueryTime = 0;
	private long PERIOD_QUERY = 4*1000;

	private boolean on_dht = false;
	
	/**
	 * Does the plugin need to send anything
	 */
	public boolean wantsToWork() {
		if (on_dht && (System.currentTimeMillis() - lastPingTime > PERIOD_PING)) return true;

		if (on_dht && (System.currentTimeMillis() - lastQueryTime > PERIOD_QUERY)) return true;
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
		bbo.flip();
		byte[] data = new byte[bbo.remaining()];
		bbo.get(data);		
		secio.write(out, data);
	}


	/**
	 * Main work method.
	 *
	 */
	public void work() {
		if (on_dht && (System.currentTimeMillis() - lastPingTime > PERIOD_PING)) {
			System.out.println("Sending a PING...");
			int dht_stream = 7;

			DHTProtos.Message msg = DHTProtos.Message.newBuilder()
							.setType(DHTProtos.Message.MessageType.PING)
							.build();

			// OK now lets send it...
			byte[] multi_data = msg.toByteArray();
			ByteBuffer vo = ByteBuffer.allocate(8192);
			Multistream.writeVarInt(vo, multi_data.length);
			vo.put(multi_data);
			vo.flip();
			byte[] multi_data2 = new byte[vo.remaining()];
			vo.get(multi_data2);
			ByteBuffer bbo = ByteBuffer.allocate(8192);
			Yamux.writeYamux(bbo, multi_data2, dht_stream, (short)0);
			secio.write(out, bbo);		// Write it out...
			
			lastPingTime = System.currentTimeMillis();	
		}

		if (on_dht && (System.currentTimeMillis() - lastQueryTime > PERIOD_QUERY)) {
			int dht_stream = 7;
			byte[] digest = new byte[32];
			for(int i=0;i<digest.length;i++) {
				digest[i] = (byte)(Math.random()*256);	
			}
			
			Multihash h = new Multihash(Multihash.Type.sha2_256, digest);														
			
			System.out.println("Sending a query for " + h);

			DHTProtos.Message msg = DHTProtos.Message.newBuilder()
							.setType(DHTProtos.Message.MessageType.FIND_NODE)
							.setKey(ByteString.copyFromUtf8(h.toString()))
							.build();

			// OK now lets send it...
			byte[] multi_data = msg.toByteArray();
			ByteBuffer vo = ByteBuffer.allocate(8192);
			Multistream.writeVarInt(vo, multi_data.length);
			vo.put(multi_data);
			vo.flip();
			byte[] multi_data2 = new byte[vo.remaining()];
			vo.get(multi_data2);
			ByteBuffer bbo = ByteBuffer.allocate(8192);
			Yamux.writeYamux(bbo, multi_data2, dht_stream, (short)0);
			secio.write(out, bbo);		// Write it out...
			System.out.println("Just sent a DHT PING");
		
			
			lastQueryTime = System.currentTimeMillis();
		}
		
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
						System.out.println(" * Switching to /secio/1.0.0");
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
								if (!using_yamux) {
									ByteBuffer inbuff = ByteBuffer.wrap(plainText);
									while(inbuff.remaining()>0) {
										String l = Multistream.readMultistream(inbuff);
										logger.fine("Multistream handshake (" + l.trim() + ")");

										if (l.equals("/multistream/1.0.0\n")) {
											ByteBuffer bb = ByteBuffer.allocate(8192);
											Multistream.writeMultistream(bb, "/multistream/1.0.0\n");
											Multistream.writeMultistream(bb, "/yamux/1.0.0\n");
											bb.flip();
											byte[] wdata = new byte[bb.remaining()];
											bb.get(wdata);		
											secio.write(out, wdata);

										} else if (l.equals("/yamux/1.0.0\n")) {
											using_yamux = true;
											System.out.println(" * Switching to /yamux/1.0.0");

											// Try starting a stream...

											writeYamuxMultistreamEnc("/multistream/1.0.0\n", 3, (short)1);
											writeYamuxMultistreamEnc("/ipfs/id/1.0.0\n", 3, (short)0);											
											
											break;
										}
									}
								} else {
									// Decode Yamux data frame
									System.out.println("DATA FRAME " + plainText.length);
									ByteBuffer inbuff = ByteBuffer.wrap(plainText);

									while(inbuff.remaining()>0) {
										byte m_ver = inbuff.get();
										byte m_type = inbuff.get();
										short m_flags = inbuff.getShort();
										int m_stream = inbuff.getInt();
										int m_length = inbuff.getInt();
										ByteBuffer inbuffp = ByteBuffer.allocate(8192);

										System.out.println("yamux ver=" + m_ver + " type=" + m_type + " flags=" + m_flags + " id=" + m_stream + " len=" + m_length);
										
										if (m_type==0) {
											byte[] d = new byte[m_length];
											inbuff.get(d);
											inbuffp.put(d);
											inbuffp.flip();
										}
	
										if (m_type==0) { // DATA
											if (m_stream==3) {
												if (!setup_stream_6) {
													while(inbuffp.remaining()>0) {
														String l = Multistream.readMultistream(inbuffp);											
														logger.info("Yamux(" + m_stream + ") Multistream handshake (" + l.trim() + ")");
														if (l.equals("/ipfs/id/1.0.0\n")) {
															setup_stream_6 = true;
															break;
														}
													}
												}
												
												if(inbuffp.remaining()>0) {
													// Read a varint
													int ll = (int)Multistream.readVarInt(inbuffp);
	
													byte[] idd = new byte[ll];
													inbuffp.get(idd);
													
													IPFSProtos.Identify ident = IPFSProtos.Identify.parseFrom(idd);
													
													// That's their ID
													String agentVersion = ident.getAgentVersion();
													String protocolVersion = ident.getProtocolVersion();
	
													byte[] pubkey = secio.remote_propose.getPubkey().toByteArray();
													
													long now = System.currentTimeMillis();
													Crawl.outputs.writeFile("ids", now + "," + host + "," + getPeerID(pubkey) + "," + agentVersion + "," + protocolVersion + "\n");

													
													System.out.println("Starting a new stream, kad...");
													writeYamuxMultistreamEnc("/multistream/1.0.0\n", 7, (short)1);
													writeYamuxMultistreamEnc("/ipfs/kad/1.0.0\n", 7, (short)0);											
												}
											}
											if (m_stream==7) {
												if (!setup_stream_7) {
	
													while(inbuffp.remaining()>0) {
														String l = Multistream.readMultistream(inbuffp);											
														logger.info("Yamux(" + m_stream + ") Multistream handshake (" + l.trim() + ")");
														if (l.equals("/ipfs/kad/1.0.0\n")) {
															setup_stream_7 = true;
															
															on_dht = true;
															
															break;
														}
													}
												}
												
												if(inbuffp.remaining()>0) {
	
													// Read a varint
													int ll = (int)Multistream.readVarInt(inbuffp);
	
													byte[] idd = new byte[ll];
													inbuffp.get(idd);
	
													DHTProtos.Message msg = DHTProtos.Message.parseFrom(idd);
	
													String msg_json = JsonFormat.printer().print(msg);
													long now2 = System.currentTimeMillis();
													Crawl.outputs.writeFile("packets", now2 + "," + msg_json + "\n");
													
	//												System.out.println("-> KAD PACKET " + msg);
													
													// Now we need to parse out closerPeers
													
													Iterator i = msg.getCloserPeersList().iterator();
													while(i.hasNext()) {
														DHTProtos.Message.Peer closer = (DHTProtos.Message.Peer)i.next();
														Multihash id = new Multihash(closer.getId().toByteArray());
														System.out.println("PEER " + id);
														
														// Parse the addrs, and see if we can connect to anything...
														Iterator j = closer.getAddrsList().iterator();
														while(j.hasNext()) {
															byte[] a = ((ByteString)j.next()).toByteArray();
															try {
																MultiAddress ma = new MultiAddress(a);
																System.out.println(" : " + ma);
																long now = System.currentTimeMillis();
																Crawl.outputs.writeFile("peers", now + "," + id + "," + ma + "\n");
																
																// For now...
																Crawl.addConnection(ma);
																
																
															} catch(Exception e) {
																// Don't care!	
															}
															// TODO: Now connect to those ones etc etc
														}
													}
												}
											} else {
											
												while(inbuffp.remaining()>0) {
													String l = Multistream.readMultistream(inbuffp);											
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
																	 .addProtocols("/ipfs/id/1.0.0")
																	 .addProtocols("/ipfs/kad/1.0.0")
																	 .build();
														System.out.println("Our ID " + id);
		
														byte[] multi_data = id.toByteArray();
														ByteBuffer vo = ByteBuffer.allocate(8192);
														Multistream.writeVarInt(vo, multi_data.length);
														vo.put(multi_data);
														vo.flip();
														byte[] multi_data2 = new byte[vo.remaining()];
														vo.get(multi_data2);
														
														ByteBuffer bbo = ByteBuffer.allocate(8192);
														
														Yamux.writeYamux(bbo, multi_data2, m_stream, (short)0);
														secio.write(out, bbo);		// Write it out...
													}
												}
											}
										} else if (m_type==1) {	// Window update
											
										} else if (m_type==2) { // ping
											// Send a ping back...
											ByteBuffer bbo = ByteBuffer.allocate(8192);
											byte[] dummy = new byte[0];
											Yamux.writeYamux(bbo, dummy, 2, m_stream, (short)2);
											secio.write(out, bbo);		// Write it out...
											logger.fine("Replied with ping");
											
										} else if (m_type==3) { // go away
											
										}
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
        Crawl.unregisterConnection(host);
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