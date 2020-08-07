package net.axod.ipfscrawl;

import net.axod.pb.*;
import net.axod.measurement.*;
import net.axod.protocols.multistream.*;

import com.google.protobuf.*;
import com.google.protobuf.util.*;

import io.ipfs.multihash.*;

import java.nio.*;

/**
 * This will do all DHT work...
 *
 */
public class DHTPlugin {
	private long lastPingTime = 0;
	private long PERIOD_PING = 10*1000;

	private long lastQueryTime = 0;
	private long PERIOD_QUERY = 4*1000;

	public boolean wantsToWork() {
		long now = System.currentTimeMillis();
		if (now - lastPingTime > PERIOD_PING) return true;
		if (now - lastQueryTime > PERIOD_QUERY) return true;
		return false;
	}
	
	// called when there is data coming in, or we signalled we want to do something
	public ByteBuffer work() {
		long now = System.currentTimeMillis();
		ByteBuffer out = ByteBuffer.allocate(8192);		// FOR NOW...

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
		
		return out;
	}
}