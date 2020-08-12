package net.axod.crypto.secio;

import net.axod.crypto.keys.*;

import java.nio.*;
import java.util.*;
import java.security.*;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class TestSecioSession {

	@Test
	public void testSecioHandshake() {
		// First, lets setup a pair of keys

		KeyPair a_mykeys = KeyManager.getNewKeys();
		KeyPair b_mykeys = KeyManager.getNewKeys();
		
		System.out.println("A keys " + a_mykeys);
		System.out.println("B keys " + b_mykeys);
		
		// Now setup some sessions...
		
		SecioSession a_secio = new SecioSession(true);
		SecioSession b_secio = new SecioSession(false);

		ByteBuffer a_in = ByteBuffer.allocate(65536);
		ByteBuffer a_out = ByteBuffer.allocate(65536);
		
		ByteBuffer b_in = ByteBuffer.allocate(65536);
		ByteBuffer b_out = ByteBuffer.allocate(65536);
		
		// Now tell them to communicate with each other until handshaked...

		try {
			for(int i=0;i<20;i++) {
				if (a_secio.handshaked() && b_secio.handshaked()) {
					System.out.println("We completed handshake after " + i + " steps");
					assertTrue(true);
					return;
				}
				
				a_secio.process(a_in, a_out, a_mykeys);
				if (a_out.position()>0) {
					a_out.flip();
					b_in.put(a_out);
					a_out.compact();
				}
				b_secio.process(b_in, b_out, b_mykeys);
				if (b_out.position()>0) {
					b_out.flip();
					a_in.put(b_out);
					b_out.compact();
				}
			}
			fail("Handshake should have completed in less than 100 steps");
		} catch(SecioException se) {
			System.err.println("Exception while handshaking...");
			fail("Exception handshaking");
		}
	}

	@Test
	public void testSecioCommunicate() {
		// First, lets setup a pair of keys

		KeyPair a_mykeys = KeyManager.getNewKeys();
		KeyPair b_mykeys = KeyManager.getNewKeys();
		
		System.out.println("A keys " + a_mykeys);
		System.out.println("B keys " + b_mykeys);
		
		// Now setup some sessions...
		
		SecioSession a_secio = new SecioSession(true);
		SecioSession b_secio = new SecioSession(false);

		ByteBuffer a_in = ByteBuffer.allocate(65536);
		ByteBuffer a_out = ByteBuffer.allocate(65536);
		
		ByteBuffer b_in = ByteBuffer.allocate(65536);
		ByteBuffer b_out = ByteBuffer.allocate(65536);
		
		// Now tell them to communicate with each other until handshaked...

		try {
			for(int i=0;i<20;i++) {
				if (a_secio.handshaked() && b_secio.handshaked()) {
					System.out.println("We completed handshake after " + i + " steps");
					
					a_secio.write(b_in, "HELLO WORLD A".getBytes());
					LinkedList llb = b_secio.process(b_in, b_out, b_mykeys);
					assertEquals(llb.size(), 1);
					byte[] data_b = (byte[])llb.get(0);
					assertTrue(Arrays.equals(data_b, "HELLO WORLD A".getBytes()));

					b_secio.write(a_in, "HELLO WORLD B".getBytes());
					LinkedList lla = a_secio.process(a_in, a_out, a_mykeys);
					assertEquals(lla.size(), 1);
					byte[] data_a = (byte[])lla.get(0);
					assertTrue(Arrays.equals(data_a, "HELLO WORLD B".getBytes()));

					return;
				}

				a_secio.process(a_in, a_out, a_mykeys);
				if (a_out.position()>0) {
					a_out.flip();
					b_in.put(a_out);
					a_out.compact();
				}
				b_secio.process(b_in, b_out, b_mykeys);
				if (b_out.position()>0) {
					b_out.flip();
					a_in.put(b_out);
					b_out.compact();
				}
			}
			fail("Handshake should have completed in less than 100 steps");
		} catch(SecioException se) {
			System.err.println("Exception while handshaking...");
			fail("Exception handshaking");
		}
	}
	
}
