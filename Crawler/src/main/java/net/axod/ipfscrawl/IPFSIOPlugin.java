package net.axod.ipfscrawl;

import net.axod.pb.*;
import net.axod.io.*;
import net.axod.handlers.*;
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

    public String host = null;

    // Negotiate multistream secio
	OutgoingMultistreamSelectSession multi_secio = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_SECIO);
	
	// This handles a SECIO session
	public SecioSession secio = new SecioSession();

	// Negotiate multistream yamux
	OutgoingMultistreamSelectSession multi_yamux = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_YAMUX);
	
	ByteBuffer yamuxInbuffer = ByteBuffer.allocate(200000);
	YamuxSession yamux = new YamuxSession();	
	boolean sentInitYamux = false;

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
		// Start with an IPFS/ID stream.
		yamux.setupOutgoingStream(new HandlerIPFSID(this));
	}

	//
	public void openDHTStream() {
		// Once we've done IPFS ID, lets open an outgoing KAD DHT stream.
		yamux.setupOutgoingStream(new HandlerKADDHT(this));
	}
	
	/**
	 * Deal with Yamux packets...
	 *
	 */
	public void processYamuxPackets(ByteBuffer inbuff) throws Exception {
		ByteBuffer yo = ByteBuffer.allocate(8192);	// For ping replies etc...
		yamux.process(inbuff, yo);
/*
		// Temporary until we get handlers setup...
		ByteBuffer in2 = yamux.getInputBuffer(2);
		if (in2!=null) {
			handleIncomingId(2, in2);	
		}
*/
		// Now we need to send anything that yamux wanted to send...
		if (yo.position()>0) {
			logger.fine("Yamux sending data... " + yo.position());
			secio.write(out, yo);		// Write it out...
		}
	}

/*
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
*/
}