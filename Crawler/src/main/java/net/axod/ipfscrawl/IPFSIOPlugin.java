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

    private ClientDetails client = new ClientDetails();
    
    public String host = null;

    public String crypto = "secio";		// or secio...
    
    OutgoingMultistreamSelectSession multi_noise = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_NOISE);
    
    
    // Negotiate multistream secio
	OutgoingMultistreamSelectSession multi_secio = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_SECIO);
	
	// This handles a SECIO session
	public SecioSession secio = new SecioSession(false);

	// Negotiate multistream yamux
	OutgoingMultistreamSelectSession multi_yamux = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_YAMUX);
	
	ByteBuffer yamuxInbuffer = ByteBuffer.allocate(200000);
	YamuxSession yamux = new YamuxSession(new HandlerIncomingFactory(client), true);	
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

		// Setup client
		client.node = n;
		client.secio = secio;
        client.host = this.host;
        client.iop = this;
	}

	private long ctime = System.currentTimeMillis();
	private long MAX_TIME = 60*1000;

	private boolean on_dht = false;
	
	/**
	 * Does the plugin need to send anything
	 */
	public boolean wantsToWork() {
		// If we're at this stage, we need to send a multistream select...
		
		if (crypto.equals("secio") && !multi_secio.sent_handshake) {
		 	return true;
		}

		if (crypto.equals("noise") && !multi_noise.sent_handshake) {
		 	return true;
		}
		
		if (secio.handshaked() && !multi_yamux.sent_handshake) {
			return true;	
		}
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

		// ======== multistream select scio ================================
		if (crypto.equals("noise") && multi_noise.process(in, out)) {
			// Now we have to do the noise protocol stuff...
			if (in.position()>0) {
				in.flip();
				byte[] a = new byte[in.remaining()];
				in.compact();
				System.out.println("NOISE DATA " + ByteUtil.toHexString(a));
			}
		}

		// ======== multistream select scio ================================
		if (crypto.equals("secio") && multi_secio.process(in, out)) {
			try {
				LinkedList spackets = secio.process(in, out, mykeys);
				
				if (secio.handshaked()) {
					for(int i=0;i<spackets.size();i++) {
						byte[] pack = (byte[])spackets.get(i);
						processSecioPacket(pack);
					}
	
					// If we need to do something inside...
					processSecioPacket(null);
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

	/**
	 * Process some secio data...
	 *
	 */
	public void processSecioPacket(byte[] plainText) throws Exception {
		if (plainText!=null) yamuxInbuffer.put(plainText);	// Add it on...

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
		yamux.setupOutgoingStream(new HandlerIPFSID(client));
	}

	//
	public void openDHTStream() {
		// Once we've done IPFS ID, lets open an outgoing KAD DHT stream.
		yamux.setupOutgoingStream(new HandlerKADDHT(client));
	}

	/**
	 * Deal with Yamux packets...
	 *
	 */
	public void processYamuxPackets(ByteBuffer inbuff) throws Exception {
		ByteBuffer yo = ByteBuffer.allocate(8192);	// For ping replies etc...
		yamux.process(inbuff, yo);

		// Now we need to send anything that yamux wanted to send...
		if (yo.position()>0) {
			logger.fine("Yamux sending data... " + yo.position());
			secio.write(out, yo);		// Write it out...
		}
	}
}