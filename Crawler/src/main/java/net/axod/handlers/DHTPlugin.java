package net.axod.handlers;

import net.axod.io.*;
import net.axod.pb.*;
import net.axod.util.*;
import net.axod.crypto.secio.*;
import net.axod.crypto.keys.*;
import net.axod.ipfscrawl.*;
import net.axod.measurement.*;
import net.axod.protocols.multistream.*;

import com.google.protobuf.*;
import com.google.protobuf.util.*;

import io.ipfs.multihash.*;
import io.ipfs.multiaddr.*;

import java.nio.*;
import java.util.*;
import java.util.logging.*;

/**
 * This handles a KAD DHT session
 *
 *
 */
public class DHTPlugin extends IOPlugin {
    private static Logger logger = Logger.getLogger("net.axod.handlers");
	
    public String source = "out";

    // Can be used to periodically send out pings
	private long lastPingTime = 0;
	private long PERIOD_PING = 10*1000;

	// Can be used to periodically send out random find_node to crawl
	private long lastQueryTime = 0;
	private long PERIOD_QUERY = 2*1000;

	// Check if we have stuff to do
	public boolean wantsToWork() {
		long now = System.currentTimeMillis();
		if (now - lastPingTime > PERIOD_PING) return true;
		if (now - lastQueryTime > PERIOD_QUERY) return true;
		return false;
	}
	
	// For now...
	ClientDetails client;
	
	// Create a new DHTPlugin
	public DHTPlugin(ClientDetails i) {
		client = i;	
	}
	
	// Do some work
    public void work() {
    	long now = System.currentTimeMillis();
    	logger.fine("DHTPlugin work " + in.position());
    	
    	// Send out a ping if we need to
		if (now - lastPingTime > PERIOD_PING) {
			DHTProtos.Message msg = DHTProtos.Message.newBuilder()
							.setType(DHTProtos.Message.MessageType.PING)
							.build();
			byte[] multi_data = msg.toByteArray();
			OutgoingMultistreamSelectSession.writeVarInt(out, multi_data.length);
			out.put(multi_data);
			DHTMetrics.incSentType(DHTProtos.Message.MessageType.PING.toString());
			lastPingTime = now;
		}

		// Send out a random find_node if we need to
		if (now - lastQueryTime > PERIOD_QUERY) {
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
			OutgoingMultistreamSelectSession.writeVarInt(out, multi_data.length);
			out.put(multi_data);
			DHTMetrics.incSentType(DHTProtos.Message.MessageType.FIND_NODE.toString());
			lastQueryTime = now;
		}

		// Read any incoming KAD packets from the network...
		in.flip();
		while(in.remaining()>0) {
			// Read a varint
			try {
				int ll = (int)OutgoingMultistreamSelectSession.readVarInt(in);
				// TODO: Protection...
				byte[] idd = new byte[ll];
				in.get(idd);

				// Progress in stream
				in.compact();
				in.flip();
				
				try {
					// Remote side...
					String rhost = client.node.getInetSocketAddress().getAddress().getHostAddress();
					int rport = client.node.getInetSocketAddress().getPort();
					
					DHTProtos.Message msg = DHTProtos.Message.parseFrom(idd);
					String msgType = msg.getType().toString();

					DHTMetrics.incRecvType(msgType);

					String msg_json = JsonFormat.printer().print(msg);
					long now2 = System.currentTimeMillis();
					Crawl.outputs.writeFile("packets", now2 + "," + msg_json + "\n");
					
					// We got a FIND_NODE (Either a reply, or a query)
					if (msgType.equals("FIND_NODE")) {

						// Go through the closer peers and log them.
						Iterator i = msg.getCloserPeersList().iterator();
						while(i.hasNext()) {
							DHTProtos.Message.Peer closer = (DHTProtos.Message.Peer)i.next();
							Multihash id = Multihash.deserialize(closer.getId().toByteArray());
							
							Iterator j = closer.getAddrsList().iterator();
							while(j.hasNext()) {
								byte[] a = ((ByteString)j.next()).toByteArray();
								try {
									MultiAddress ma = new MultiAddress(a);
									Crawl.outputs.writeFile("peers", now2 + "," + source + "," + id + "," + ma + "\n");
									
									// For now, ask Crawl to connect to each one...
									Crawl.addConnection(ma);
								} catch(Exception e) {
									System.err.println("DHT Exception decoding MultiAddress " + ByteUtil.toHexString(a) + " " + e);
									// Don't care!	
								}
							}
						}
					} else if (msgType.equals("PING")) {
						// TODO: Send a pong? How do we know if it's a ping or a pong?
						Crawl.outputs.writeFile("dht_ping", now2 + "," + rhost + "," + rport + "\n");
					} else if (msgType.equals("ADD_PROVIDER")) {
						String key = ByteUtil.toHexString(msg.getKey().toByteArray());
						String mhkey = "";
						try {
							Multihash mkey = Multihash.deserialize(msg.getKey().toByteArray());
							mhkey = mkey.toString();
						} catch(RuntimeException e) {
							System.err.println("Multihash issue? " + e);	
						}
						Crawl.outputs.writeFile("dht_add_provider", now2 + "," + rhost + "," + rport + "," + key + "," + mhkey + "\n");
					} else if (msgType.equals("GET_PROVIDERS")) {
						String key = ByteUtil.toHexString(msg.getKey().toByteArray());
						String mhkey = "";
						try {
							Multihash mkey = Multihash.deserialize(msg.getKey().toByteArray());
							mhkey = mkey.toString();
						} catch(RuntimeException e) {
							System.err.println("Multihash issue? " + e);	
						}
						Crawl.outputs.writeFile("dht_get_providers", now2 + "," + rhost + "," + rport + "," + key + "," + mhkey + "\n");
					}
				} catch(Exception e) {
					System.err.println("DHT Exception: " + e);
					// Issue working with kad...
				}
				
			} catch(BufferUnderflowException bue) {
				in.rewind();
				// Wait until we have some more data...
				break;
			}
		}
		in.compact();
    }
    
    public void closing() {
    }
}