package net.axod.handlers;

import net.axod.io.*;
import net.axod.protocols.multistream.*;
import net.axod.ipfscrawl.*;
import net.axod.crypto.keys.*;
import net.axod.protocols.plugins.*;
import net.axod.util.*;
import net.axod.pb.*;

import io.ipfs.multiaddr.*;

import java.nio.*;
import java.net.*;

public class HandlerIncoming extends IOPlugin {
	ClientDetails client = null;
	
	IncomingMultistreamSelectSession multi = new IncomingMultistreamSelectSession();

	boolean id_sent = false;
	
	DHTPlugin dht = null;			// If we're accepting DHT

	public HandlerIncoming(ClientDetails i) {
		client = i;	
	}

	public boolean wantsToWork() {
		if (multi.hasHandshaked()) {
			if (multi.getProtocol().equals(OutgoingMultistreamSelectSession.PROTO_ID) && !id_sent) {
				return true;	// We want to send our ID...	
			}
			if (multi.getProtocol().equals(OutgoingMultistreamSelectSession.PROTO_DHT)) {
				return dht.wantsToWork();
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
					dht = new DHTPlugin(client);
					dht.source = "yamuxin";
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
				// Their observed address..

				InetSocketAddress isa = client.node.getInetSocketAddress();
				boolean isIPv6 = (isa.getAddress() instanceof Inet6Address);
				
				MultiAddress observed = new MultiAddress("/ip" + (isIPv6?"6":"4") + "/" + isa.getAddress().getHostAddress() + "/tcp/" + isa.getPort());

				//System.out.println("Observed " + observed.toString());

				try {
					String local_peerID = KeyManager.getPeerID(client.secio.getLocalPublicKey()).toString();
					String remote_peerID = KeyManager.getPeerID(client.secio.getRemotePublicKey()).toString();
	
					byte[] multi_data2 = IdentifyPlugin.getIdentify(client.secio.getLocalPublicKey(), local_peerID, remote_peerID, observed);
					out.put(multi_data2);
				} catch(Exception e) {
					System.err.println("Exception constructing identify packet");	
				}
				id_sent = true;
			}
			// Now we can work with the data...

			if (multi.getProtocol().equals(OutgoingMultistreamSelectSession.PROTO_DHT)) {
				//System.out.println("IN DHT Working on yamuxin DHT session... " + in.position());
				
				// First copy the in buffer...
				if (in.position()>0) {
					in.flip();
					dht.in.put(in);
					in.compact();
				}

				dht.work();

				if (dht.out.position()>0) {
					dht.out.flip();
					out.put(dht.out);
					dht.out.compact();
				}
				
				//System.out.println("IN DHT Yamuxin output " + out.position());
			}

			if (multi.getProtocol().equals(OutgoingMultistreamSelectSession.PROTO_BITSWAP)) {
				if (in.position()>0) {
					in.flip();
					int ll = (int)OutgoingMultistreamSelectSession.readVarInt(in);
					byte[] dat = new byte[ll];
					in.get(dat);
					in.compact();
					
					try {
						Bitswap.Message m = Bitswap.Message.parseFrom(dat);
						
						Crawl.outputs.writeFile("data_bitswap", now + "," + m + "\n");
					} catch(Exception e) {
						System.err.println("Exception bitswap " + e);	
					}
				}
			}
		}

		byte[] o = new byte[out.position()];
		out.flip();
		out.get(o);
		out.rewind();
		out.compact();

		//System.out.println("WRITING " + iop.host + " " + multi.getProtocol() + " " + multi.hasHandshaked() + " " + ByteUtil.toHexString(o));
	}

	public void closing() {
		
	}
}