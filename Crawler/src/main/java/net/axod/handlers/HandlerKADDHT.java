package net.axod.handlers;

import net.axod.io.*;
import net.axod.pb.*;
import net.axod.util.*;
import net.axod.protocols.multistream.*;
import net.axod.crypto.secio.*;
import net.axod.crypto.keys.*;
import net.axod.ipfscrawl.*;
import net.axod.measurement.*;

import com.google.protobuf.*;
import com.google.protobuf.util.*;

import io.ipfs.multihash.*;
import io.ipfs.multiaddr.*;

import java.nio.*;
import java.util.*;
import java.util.logging.*;

/**
 * This handles an outgoing KAD DHT
 *
 */
public class HandlerKADDHT extends IOPlugin {
    private static Logger logger = Logger.getLogger("net.axod.handlers");

	OutgoingMultistreamSelectSession multi_dht = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_DHT);
    
	boolean sent_handshake = false;

	public boolean on_the_dht = false;

	private IOPlugin dht;

	public boolean wantsToWork() {
    	if (!sent_handshake) {
    		sent_handshake = true;
    		return true;
    	}

		long now = System.currentTimeMillis();
		if (!on_the_dht) return false;
		return dht.wantsToWork();
	}
	
	public HandlerKADDHT(IPFSIOPlugin i) {
		dht = new DHTPlugin(i);
	}
	
    public void work() {
    	long now = System.currentTimeMillis();

		if (multi_dht.process(in, out)) {
			if (!on_the_dht) {
				logger.fine("Negotiated KAD DHT");
				on_the_dht = true;
			}
			
			// Copy any input...
			if (in.position()>0) {
				in.flip();
				dht.in.put(in);
				in.compact();
			}
			dht.work();    		
		}

    	// Now copy any buffer contents...
    	if (dht.out.position()>0) {
    		dht.out.flip();
    		out.put(dht.out);
    		dht.out.compact();
    	}
    }
    
    public void closing() {
    }
}