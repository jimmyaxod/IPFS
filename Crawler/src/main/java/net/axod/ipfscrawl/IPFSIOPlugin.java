package net.axod.ipfscrawl;

import net.axod.pb.*;
import net.axod.io.*;
import net.axod.protocols.*;
import net.axod.protocols.plugins.*;
import net.axod.protocols.multistream.*;
import net.axod.protocols.yamux.*;
import net.axod.crypto.secio.*;
import net.axod.crypto.keys.*;
import net.axod.util.*;
import net.axod.measurement.*;


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
	OutgoingMultistreamSelectSession multi_secio = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_SECIO);
	
	// This handles a SECIO session
	SecioSession secio = new SecioSession();

	// Negotiate multistream yamux
	OutgoingMultistreamSelectSession multi_yamux = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_YAMUX);
	
	// This will handle everything related to the dht...
	DHTPlugin dht = new DHTPlugin();
	
	
	ByteBuffer yamuxInbuffer = ByteBuffer.allocate(200000);

	YamuxSession yamux = new YamuxSession();
	
	boolean sentInitYamux = false;

	boolean setup_stream_6 = false;
	boolean setup_stream_4 = false;

	// My RSA keys
	static KeyPair mykeys = null;	

	static {
		mykeys = KeyManager.getKeys();
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
	}

	private long ctime = System.currentTimeMillis();
	private long MAX_TIME = 60*1000;
	
	private boolean on_dht = false;
	
	/**
	 * Does the plugin need to send anything
	 */
	public boolean wantsToWork() {
		long now = System.currentTimeMillis();
		if (dht.wantsToWork()) return true;		
		if (now - ctime > MAX_TIME) return true;
		return false;	
	}

	/**
	 * Main work method.
	 *
	 */
	public void work() {
		long now = System.currentTimeMillis();
		if (now - ctime > MAX_TIME) {
			close();
			return;
		}

		int dht_stream = 9;

		if (on_dht) {
			if (dht.wantsToWork()) {
				ByteBuffer dht_out = dht.work(null);	// Nothing to go in...

				if(dht_out!=null && dht_out.position()>0) {
					try {
						dht_out.flip();
						byte[] multi_data2 = new byte[dht_out.remaining()];
						dht_out.get(multi_data2);

						ByteBuffer bbo = ByteBuffer.allocate(8192);
						YamuxSession.writeYamux(bbo, multi_data2, dht_stream, (short)0);
						secio.write(out, bbo);		// Write it out...
					} catch(SecioException se) {
						logger.warning("Could not write DHT packet");
					}
				}			
			}
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
				} catch(BufferUnderflowException bue) {
					logger.info("Exception processing packet underflow " + bue);
					bue.printStackTrace();					
				} catch(Exception e) {
					logger.info("Exception processing packet " + e);
					e.printStackTrace();
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
		yamuxInbuffer.put(plainText);	// Add it on...
		
		ByteBuffer outbuff = ByteBuffer.allocate(8192);		// For now...
		
		// multistream select yamux
		if (multi_yamux.process(yamuxInbuffer, outbuff)) {
			if (!sentInitYamux) {
				// Start up a new yamux stream...
				initYamuxStreams();
				sentInitYamux = true;
			}
			processYamuxPackets(yamuxInbuffer);
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

	public void closing() {
		logger.fine("Connection closing...");
        Crawl.unregisterConnection(host);
	}	

	// ==== Under here needs tidyup

	private void initYamuxStreams() {
		writeYamuxMultistreamEnc("/multistream/1.0.0\n", 3, (short)1);
		writeYamuxMultistreamEnc("/ipfs/id/1.0.0\n", 3, (short)0);	
		yamux.setupStream(3);
	}

	/**
	 * Deal with Yamux packets...
	 *
	 */
	public void processYamuxPackets(ByteBuffer inbuff) throws Exception {
		ByteBuffer yo = ByteBuffer.allocate(8192);	// For ping replies etc...
		yamux.process(inbuff, yo);

		// Handle streams...
		handleStream3(yamux.getInputBuffer(3));
		handleStream4(yamux.getInputBuffer(9));
		
		// Temporary until we get handlers setup...
		ByteBuffer in2 = yamux.getInputBuffer(2);
		if (in2!=null) {
			handleIncomingId(2, in2);	
		}

		// Now we need to send anything that yamux wanted to send...
		if (yo.position()>0) {
			logger.fine("Yamux sending data... " + yo.position());
			secio.write(out, yo);		// Write it out...
		}
	}

	public void handleIncomingId(int m_stream, ByteBuffer inbuffp) throws Exception {		
		inbuffp.flip();
		while(inbuffp.remaining()>0) {
			String l = OutgoingMultistreamSelectSession.readMultistream(inbuffp);								

			if (l.equals("/multistream/1.0.0\n")) {
				writeYamuxMultistreamEnc("/multistream/1.0.0\n", m_stream, (short)2);
				writeYamuxMultistreamEnc("/ipfs/id/1.0.0\n", m_stream, (short)0);

			} else if (l.equals("/ipfs/id/1.0.0\n")) {
				String local_peerID = KeyManager.getPeerID(secio.getLocalPublicKey()).toString();
				String remote_peerID = KeyManager.getPeerID(secio.getRemotePublicKey()).toString();

				byte[] multi_data2 = IdentifyPlugin.getIdentify(secio.getLocalPublicKey(), local_peerID, remote_peerID);
				// Write it to the output
				ByteBuffer bbo = ByteBuffer.allocate(8192);
				YamuxSession.writeYamux(bbo, multi_data2, m_stream, (short)0);
				secio.write(out, bbo);		// Write it out...
			}
		}
		inbuffp.compact();
	}
	
	/**
	 * For now, this is just doing ipfs/id on stream 3...
	 *
	 */
	public void handleStream3(ByteBuffer inbuffp) throws Exception {
		if (inbuffp==null) return;
		inbuffp.flip();
		if (!setup_stream_6) {
			while(inbuffp.remaining()>0) {
				// TODO: Break on failure...
				String l = OutgoingMultistreamSelectSession.readMultistream(inbuffp);											
				logger.fine("Yamux(ipfs/id) Multistream handshake (" + l.trim() + ")");
				if (l.equals("/ipfs/id/1.0.0\n")) {
					setup_stream_6 = true;
					break;
				}
			}
		}

		while(inbuffp.remaining()>0) {
			// Read a varint
			try {
				int ll = (int)OutgoingMultistreamSelectSession.readVarInt(inbuffp);

				byte[] idd = new byte[ll];
				inbuffp.get(idd);

				// Progress...
				inbuffp.compact();
				inbuffp.flip();

				IPFSProtos.Identify ident = IPFSProtos.Identify.parseFrom(idd);

				System.out.println("IDENT " + ident);

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
				
				byte[] pubkey = secio.getRemotePublicKey();

				long now = System.currentTimeMillis();
				Crawl.outputs.writeFile("ids", now + "," + host + "," + KeyManager.getPeerID(pubkey) + "," + agentVersion + "," + protocolVersion + "," + protocols + "\n");
				
				//System.out.println("Starting a new stream, kad...");
				yamux.setupStream(9);
				writeYamuxMultistreamEnc("/multistream/1.0.0\n", 9, (short)1);
				writeYamuxMultistreamEnc("/ipfs/kad/1.0.0\n", 9, (short)0);
			} catch(BufferUnderflowException bue) {
				inbuffp.rewind();
				// Wait until we have some more data...
				break;
			}
		}
		inbuffp.compact();
	}

	/**
	 *
	 */
	public void handleStream4(ByteBuffer inbuffp) throws Exception {
		int dht_stream = 9;
		if (inbuffp==null) return;
		inbuffp.flip();

		if (!setup_stream_4) {
			while(inbuffp.remaining()>0) {
				String l = OutgoingMultistreamSelectSession.readMultistream(inbuffp);											
				logger.fine("Yamux Multistream handshake (" + l.trim() + ")");
				if (l.equals("/ipfs/kad/1.0.0\n")) {
					setup_stream_4 = true;
					on_dht = true;
					//System.out.println("ON THE DHT");
					break;
				}
			}
		}
		inbuffp.compact();
		
		if (on_dht) {
			ByteBuffer dht_out = dht.work(inbuffp);
			
			// Send anything...
			if(dht_out!=null && dht_out.position()>0) {
				try {
					dht_out.flip();
					byte[] multi_data2 = new byte[dht_out.remaining()];
					dht_out.get(multi_data2);

					ByteBuffer bbo = ByteBuffer.allocate(8192);
					YamuxSession.writeYamux(bbo, multi_data2, dht_stream, (short)0);
					secio.write(out, bbo);		// Write it out...
				} catch(SecioException se) {
					logger.warning("Could not write DHT packet");
				}
			}			
		}
	}

	private void writeYamuxMultistreamEnc(String d, int m_stream, short m_flags) {
		try {
			ByteBuffer bbm = ByteBuffer.allocate(8192);
			OutgoingMultistreamSelectSession.writeMultistream(bbm, d);		
			bbm.flip();
			byte[] multi_data = new byte[bbm.remaining()];
			bbm.get(multi_data);
	
			ByteBuffer bbo = ByteBuffer.allocate(8192);
			YamuxSession.writeYamux(bbo, multi_data, m_stream, m_flags);
			bbo.flip();
			byte[] data = new byte[bbo.remaining()];
			bbo.get(data);		
			secio.write(out, data);
		} catch(SecioException se) {
			// For now, we don't care...			
		}
	}
	
}