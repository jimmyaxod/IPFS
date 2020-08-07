package net.axod.protocols.plugins;

import net.axod.protocols.multistream.*;
import net.axod.pb.*;

import java.nio.*;

import io.ipfs.multiaddr.*;

import com.google.protobuf.*;
import com.google.protobuf.util.*;


/**
 * Handles a request for Identify
 *
 */
public class IdentifyPlugin {

	public static byte[] getIdentify(byte[] publickey, String local_peerID, String remote_peerID) {
		MultiAddress listen1 = new MultiAddress("/ip4/86.171.62.88/tcp/3399");
		MultiAddress observed1 = new MultiAddress("/ip4/86.171.62.88/tcp/3399");	// TODO: Fix

		IPFSProtos.Identify id = IPFSProtos.Identify.newBuilder()
					 .setProtocolVersion("ipfs/0.1.0")
					 .setAgentVersion("mindYourOwnBusiness/0.0.1")
					 .setPublicKey(ByteString.copyFrom(publickey))
					 .addListenAddrs(ByteString.copyFrom(listen1.getBytes()))
					 .setObservedAddr(ByteString.copyFrom(observed1.getBytes()))		// TODO: Fix this...
					 .addProtocols("/ipfs/id/1.0.0")
					 .addProtocols("/ipfs/kad/1.0.0")
					 .addProtocols("/x/")
					 .addProtocols("/ipfs/dht")
					 .addProtocols("/ipfs/ping/1.0.0")
					 .build();

		//System.out.println("Identify " + id);
					 
		byte[] multi_data = id.toByteArray();
		ByteBuffer vo = ByteBuffer.allocate(8192);
		OutgoingMultistreamSelectSession.writeVarInt(vo, multi_data.length);
		vo.put(multi_data);
		vo.flip();
		byte[] multi_data2 = new byte[vo.remaining()];
		vo.get(multi_data2);
		return multi_data2;
	}
	
}