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

    // Negotiate multistream secio
	MultistreamSelectSession multi_secio = new MultistreamSelectSession(MultistreamSelectSession.PROTO_SECIO);
	
	// This handles a SECIO session
	SecioSession secio = new SecioSession();

	// Negotiate multistream yamux
	MultistreamSelectSession multi_yamux = new MultistreamSelectSession(MultistreamSelectSession.PROTO_YAMUX);
	
	boolean sentInitYamux = false;

	boolean setup_stream_6 = false;
	boolean setup_stream_7 = false;
		
	// My RSA keys
	KeyPair mykeys = null;	

	// Some stats...
	static long total_sent_pings = 0;
	static long total_sent_find_node = 0;
	
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
		MultistreamSelectSession.writeMultistream(bbm, d);		
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
			int dht_stream = 7;

			DHTProtos.Message msg = DHTProtos.Message.newBuilder()
							.setType(DHTProtos.Message.MessageType.PING)
							.build();

			// OK now lets send it...
			byte[] multi_data = msg.toByteArray();
			ByteBuffer vo = ByteBuffer.allocate(8192);
			MultistreamSelectSession.writeVarInt(vo, multi_data.length);
			vo.put(multi_data);
			vo.flip();
			byte[] multi_data2 = new byte[vo.remaining()];
			vo.get(multi_data2);
			ByteBuffer bbo = ByteBuffer.allocate(8192);
			Yamux.writeYamux(bbo, multi_data2, dht_stream, (short)0);
			secio.write(out, bbo);		// Write it out...
			total_sent_pings++;
			
			lastPingTime = System.currentTimeMillis();	
		}

		if (on_dht && (System.currentTimeMillis() - lastQueryTime > PERIOD_QUERY)) {
			int dht_stream = 7;
			byte[] digest = new byte[32];
			for(int i=0;i<digest.length;i++) {
				digest[i] = (byte)(Math.random()*256);	
			}
			
			Multihash h = new Multihash(Multihash.Type.sha2_256, digest);														
			
			DHTProtos.Message msg = DHTProtos.Message.newBuilder()
							.setType(DHTProtos.Message.MessageType.FIND_NODE)
							.setKey(ByteString.copyFromUtf8(h.toString()))
							.build();

			// OK now lets send it...
			byte[] multi_data = msg.toByteArray();
			ByteBuffer vo = ByteBuffer.allocate(8192);
			MultistreamSelectSession.writeVarInt(vo, multi_data.length);
			vo.put(multi_data);
			vo.flip();
			byte[] multi_data2 = new byte[vo.remaining()];
			vo.get(multi_data2);
			ByteBuffer bbo = ByteBuffer.allocate(8192);
			Yamux.writeYamux(bbo, multi_data2, dht_stream, (short)0);
			secio.write(out, bbo);		// Write it out...
			total_sent_find_node++;
			
			lastQueryTime = System.currentTimeMillis();
		}
		
		logger.fine("Work " + in);
		
		if (in.position()>0) {
			// ======== multistream select scio ================================
			if (multi_secio.process(in, out)) {
				try {
					LinkedList spackets = secio.process(in, out, mykeys);
					for(int i=0;i<spackets.size();i++) {
						byte[] pack = (byte[])spackets.get(i);
						processSecioPacket(pack);
					}
				} catch(SecioException se) {
					logger.info("Exception within secio " + se);
					close();
					return;
				} catch(Exception e) {
					logger.info("Exception processing packet " + e);
					close();
					return;					
				}
			}
		}
	}

	/**
	 * Process some secio data...
	 *
	 */
	public void processSecioPacket(byte[] plainText) throws Exception {
		ByteBuffer inbuff = ByteBuffer.wrap(plainText);
		inbuff.compact();
		
		ByteBuffer outbuff = ByteBuffer.allocate(8192);		// For now...
		
		// multistream select yamux
		if (multi_yamux.process(inbuff, outbuff)) {
			if (!sentInitYamux) {
				writeYamuxMultistreamEnc("/multistream/1.0.0\n", 3, (short)1);
				writeYamuxMultistreamEnc("/ipfs/id/1.0.0\n", 3, (short)0);											
				sentInitYamux = true;
			}
			processYamuxPackets(inbuff);
		}
		
		// Send any multistream handshake stuff to next layer
		outbuff.flip();
		if (outbuff.remaining()>0) {
			logger.fine("Sending data " + outbuff.remaining());
			byte[] wdata = new byte[outbuff.remaining()];
			outbuff.get(wdata);
			secio.write(out, wdata);
		}
	}	

	/**
	 * Process Yamux packet
	 *
	 */
	public void processYamuxPackets(ByteBuffer inbuff) throws Exception {	
		inbuff.flip();
		while(inbuff.remaining()>0) {
			byte m_ver = inbuff.get();
			byte m_type = inbuff.get();
			short m_flags = inbuff.getShort();
			int m_stream = inbuff.getInt();
			int m_length = inbuff.getInt();
			ByteBuffer inbuffp = ByteBuffer.allocate(8192);

			//System.out.println("yamux ver=" + m_ver + " type=" + m_type + " flags=" + m_flags + " id=" + m_stream + " len=" + m_length);
			
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
							String l = MultistreamSelectSession.readMultistream(inbuffp);											
							logger.fine("Yamux(" + m_stream + ") Multistream handshake (" + l.trim() + ")");
							if (l.equals("/ipfs/id/1.0.0\n")) {
								setup_stream_6 = true;
								break;
							}
						}
					}
					
					if(inbuffp.remaining()>0) {
						// Read a varint
						int ll = (int)MultistreamSelectSession.readVarInt(inbuffp);

						byte[] idd = new byte[ll];
						inbuffp.get(idd);
						
						IPFSProtos.Identify ident = IPFSProtos.Identify.parseFrom(idd);
						
						//System.out.println("IDENT " + ident);
						
						// That's their ID
						String agentVersion = ident.getAgentVersion();
						String protocolVersion = ident.getProtocolVersion();
						String protocols = "";
						Iterator i = ident.getProtocolsList().iterator();
						while(i.hasNext()) {
							String pro = (String)i.next();
							if (protocols.length()>0) protocols+=" ";
							protocols+=pro;
						}
						
						byte[] pubkey = secio.remote_propose.getPubkey().toByteArray();
						
						long now = System.currentTimeMillis();
						Crawl.outputs.writeFile("ids", now + "," + host + "," + getPeerID(pubkey) + "," + agentVersion + "," + protocolVersion + "," + protocols + "\n");

						
						//System.out.println("Starting a new stream, kad...");
						writeYamuxMultistreamEnc("/multistream/1.0.0\n", 7, (short)1);
						writeYamuxMultistreamEnc("/ipfs/kad/1.0.0\n", 7, (short)0);											
					}
				}
				if (m_stream==7) {
					if (!setup_stream_7) {

						while(inbuffp.remaining()>0) {
							String l = MultistreamSelectSession.readMultistream(inbuffp);											
							//logger.info("Yamux(" + m_stream + ") Multistream handshake (" + l.trim() + ")");
							if (l.equals("/ipfs/kad/1.0.0\n")) {
								setup_stream_7 = true;
								
								on_dht = true;
								
								break;
							}
						}
					}
					
					if(inbuffp.remaining()>0) {

						// Read a varint
						int ll = (int)MultistreamSelectSession.readVarInt(inbuffp);

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
							//System.out.println("PEER " + id);
							
							// Parse the addrs, and see if we can connect to anything...
							Iterator j = closer.getAddrsList().iterator();
							while(j.hasNext()) {
								byte[] a = ((ByteString)j.next()).toByteArray();
								try {
									MultiAddress ma = new MultiAddress(a);
								//	System.out.println(" : " + ma);
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
						String l = MultistreamSelectSession.readMultistream(inbuffp);											
//						logger.info("Yamux(" + m_stream + ") Multistream handshake (" + l.trim() + ")");

						if (l.equals("/multistream/1.0.0\n")) {

							writeYamuxMultistreamEnc("/multistream/1.0.0\n", m_stream, (short)2);
							writeYamuxMultistreamEnc("/ipfs/id/1.0.0\n", m_stream, (short)0);

						} else if (l.equals("/ipfs/id/1.0.0\n")) {
							IPFSProtos.Identify id = IPFSProtos.Identify.newBuilder()
										 .setProtocolVersion("ipfs/0.1.0")
										 .setAgentVersion("mindYourOwnBusiness/0.0.1")
										 .setPublicKey(ByteString.copyFrom(secio.local_propose.getPubkey().toByteArray()))
										 .addListenAddrs(ByteString.copyFromUtf8("/ip4/86.171.62.88/tcp/4001/p2p/QmUXRZsrivZbvUcVPG1HPay5rnwhwoFAPpi1baLr11v4nf"))
										 .setObservedAddr(ByteString.copyFromUtf8("/ip4/86.171.62.88/tcp/4001/p2p/QmUXRZsrivZbvUcVPG1HPay5rnwhwoFAPpi1baLr11v4nf"))
										 .addProtocols("/ipfs/id/1.0.0")
										 .addProtocols("/ipfs/kad/1.0.0")
										 .build();

							byte[] multi_data = id.toByteArray();
							ByteBuffer vo = ByteBuffer.allocate(8192);
							MultistreamSelectSession.writeVarInt(vo, multi_data.length);
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