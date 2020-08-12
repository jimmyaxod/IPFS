package net.axod.protocols.multistream;


import java.nio.*;
import java.util.*;
import java.security.*;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class TestMultistream {

	@Test
	public void testMultistream() {
		OutgoingMultistreamSelectSession a_multi = new OutgoingMultistreamSelectSession(OutgoingMultistreamSelectSession.PROTO_SECIO);
		IncomingMultistreamSelectSession b_multi = new IncomingMultistreamSelectSession();
		
		ByteBuffer a_in = ByteBuffer.allocate(65536);
		ByteBuffer a_out = ByteBuffer.allocate(65536);
		
		ByteBuffer b_in = ByteBuffer.allocate(65536);
		ByteBuffer b_out = ByteBuffer.allocate(65536);
		
		// Do the handshake...
		for(int i=0;i<10;i++) {
			boolean a_complete = a_multi.process(a_in, a_out);
			if (a_complete) {
				System.out.println("a_complete");	
			}
			
			if (a_out.position()>0) {
				a_out.flip();
				b_in.put(a_out);
				a_out.compact();
			}
			
			String b_protocol = b_multi.process(b_in, b_out);
			if (b_out.position()>0) {
				b_out.flip();
				a_in.put(b_out);
				b_out.compact();
			}
			if (b_protocol!=null) {
				System.out.println("Protocol [" + b_protocol + "]");
				assertEquals(b_protocol, OutgoingMultistreamSelectSession.PROTO_SECIO);
				
				// NB Haven't completed handshake fully yet
				return;
			}
		}
		
		fail("Multistream should complete in less than 10 steps");
	}
	
}