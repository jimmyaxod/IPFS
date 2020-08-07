package net.axod.handlers;

import net.axod.io.*;
import net.axod.pb.*;
import net.axod.protocols.multistream.*;
import net.axod.crypto.secio.*;
import net.axod.crypto.keys.*;
import net.axod.ipfscrawl.*;

import java.nio.*;
import java.util.*;
import java.util.logging.*;

/**
 * This handles an outgoing IPFS ID Request
 *
 */
public class HandlerIPFSID extends IOPlugin {
    private static Logger logger = Logger.getLogger("net.axod.handlers");

	OutgoingMultistreamSelectSession multi_id = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_ID);
    
	boolean sent_handshake = false;

	// For now...
	IPFSIOPlugin iop;
	
	public HandlerIPFSID(IPFSIOPlugin i) {
		this.iop = i;	
	}
	
    public void work() {
    	logger.fine("HandlerIPFSID work " + in.position());
		if (multi_id.process(in, out)) {
			// Now we can work at the IPFS/ID level...
			in.flip();
			while(in.remaining()>0) {
				// Read a varint
				try {
					int ll = (int)OutgoingMultistreamSelectSession.readVarInt(in);
					byte[] idd = new byte[ll];
					in.get(idd);

					// Progress...
					in.compact();
					in.flip();
					
					try {
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
	
						byte[] pubkey = iop.secio.getRemotePublicKey();
						String peerID = KeyManager.getPeerID(pubkey).toString();
						
						long now = System.currentTimeMillis();
						Crawl.outputs.writeFile("ids", now + "," + iop.host + "," + peerID + "," + agentVersion + "," + protocolVersion + "," + protocols + "\n");
					
						close();
						
						iop.openDHTStream();
					} catch(Exception e) {
						// Issue working with ident...	
					}
					
				} catch(BufferUnderflowException bue) {
					in.rewind();
					// Wait until we have some more data...
					break;
				}
			}
			in.compact();
		}
    }
    
    public boolean wantsToWork() {
    	if (!sent_handshake) {
    		sent_handshake = true;
    		return true;
    	}
    	return false;	
    }
    
    public void closing() {
    }
}