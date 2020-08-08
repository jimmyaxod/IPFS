package net.axod.handlers;

import net.axod.io.*;
import net.axod.protocols.multistream.*;
import net.axod.ipfscrawl.*;
import net.axod.crypto.keys.*;
import net.axod.protocols.plugins.*;

import java.nio.*;

public class HandlerIncoming extends IOPlugin {
	IPFSIOPlugin iop = null;

	IncomingMultistreamSelectSession multi = new IncomingMultistreamSelectSession();

	boolean id_sent = false;

	public HandlerIncoming(IPFSIOPlugin i) {
		iop = i;	
	}

	public boolean wantsToWork() {
		if (multi.hasHandshaked()) {
			if (multi.getProtocol().equals(OutgoingMultistreamSelectSession.PROTO_ID) && !id_sent) {
				return true;	// We want to send our ID...	
			}
		}
		return false;
	}

	public void work() {
		long now = System.currentTimeMillis();

		if (!multi.hasHandshaked()) {
			String proto = multi.process(in, out);
			if (proto!=null) {				
				// For now, log it...
				Crawl.outputs.writeFile("in_protocols", now + "," + proto.trim() + "\n");

				if (proto.equals(OutgoingMultistreamSelectSession.PROTO_ID)) {
					multi.sendAccept(out);
				} else if (proto.equals(OutgoingMultistreamSelectSession.PROTO_DHT)) {
					multi.sendAccept(out);
					System.out.println("Sent accept for protocol DHT");
				} else if (proto.equals(OutgoingMultistreamSelectSession.PROTO_BITSWAP)) {
					multi.sendAccept(out);
					System.out.println("Sent accept for protocol BITSWAP");
				} else {
					multi.sendReject(out);
					multi.reset();
				}
			}
		} else {
			if (multi.getProtocol().equals(OutgoingMultistreamSelectSession.PROTO_ID) && !id_sent) {
				try {
					String local_peerID = KeyManager.getPeerID(iop.secio.getLocalPublicKey()).toString();
					String remote_peerID = KeyManager.getPeerID(iop.secio.getRemotePublicKey()).toString();
	
					byte[] multi_data2 = IdentifyPlugin.getIdentify(iop.secio.getLocalPublicKey(), local_peerID, remote_peerID);
					out.put(multi_data2);
				} catch(Exception e) {
					System.err.println("Exception constructing identify packet");	
				}
				id_sent = true;
			}
			// Now we can work with the data...
			
			if (in.position()>0) {
				System.out.println("INDATA (" + multi.getProtocol().trim() + ") data " + in.position());
			}
		}
	}

	public void closing() {
		
	}
}