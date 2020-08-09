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
    
	private long lastPingTime = 0;
	private long PERIOD_PING = 10*1000;

	private long lastQueryTime = 0;
	private long PERIOD_QUERY = 2*1000;

	public boolean wantsToWork() {
		long now = System.currentTimeMillis();
		if (now - lastPingTime > PERIOD_PING) return true;
		if (now - lastQueryTime > PERIOD_QUERY) return true;
		return false;
	}
	
	// For now...
	IPFSIOPlugin iop;
	
	public DHTPlugin(IPFSIOPlugin i) {
		this.iop = i;	
	}
	
    public void work() {
    	long now = System.currentTimeMillis();
    	logger.fine("DHTPlugin work " + in.position());
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
    	
		// Now we can work at the KAD DHT level...
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
					DHTProtos.Message msg = DHTProtos.Message.parseFrom(idd);

					DHTMetrics.incRecvType(msg.getType().toString());
					
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
								Crawl.outputs.writeFile("peers", now + "," + source + "," + id + "," + ma + "\n");
								
								// For now, ask Crawl to connect to each one...
								Crawl.addConnection(ma);
							} catch(Exception e) {
								System.err.println("DHT Exception decoding MultiAddress " + ByteUtil.toHexString(a) + " " + e);
								// Don't care!	
							}
						}
					}
				} catch(Exception e) {
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