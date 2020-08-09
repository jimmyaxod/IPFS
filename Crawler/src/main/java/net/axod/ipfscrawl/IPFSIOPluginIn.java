package net.axod.ipfscrawl;

import net.axod.io.*;
import net.axod.ipfscrawl.*;
import net.axod.protocols.multistream.*;
import net.axod.crypto.keys.*;
import net.axod.crypto.secio.*;

import java.nio.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;
import java.security.*;

public class IPFSIOPluginIn extends IOPlugin {
	IncomingMultistreamSelectSession multi = new IncomingMultistreamSelectSession();

	// My RSA keys
	static KeyPair mykeys = null;	

	static {
		mykeys = KeyManager.getKeys();
	}

	SecioSession secio;
	boolean sent_secio_starter = false;
	
	public IPFSIOPluginIn(Node n, InetSocketAddress isa) {
		System.out.println("INCOMING CONNECTION " + n + " on " + isa);
	}

	public boolean wantsToWork() {
		if (secio!=null & !sent_secio_starter) return true;
		return false;
	}

	public void work() {
		long now = System.currentTimeMillis();

		System.out.println("INCOMING CONNECTION work " + in.position());
		
		if (!multi.hasHandshaked()) {
			String proto = multi.process(in, out);
			System.out.println("PROTOCOL " + proto);
			if (proto!=null) {				
				// For now, log it...
				Crawl.outputs.writeFile("in_connect_protocols", now + "," + proto.trim() + "\n");
				if (proto.equals(OutgoingMultistreamSelectSession.PROTO_SECIO)) {
					multi.sendAccept(out);
					System.out.println("Sent accept for secio...");
					secio = new SecioSession();
				} else {
					close();
					return;
				}
			}
		} else {
			if (multi.getProtocol().equals(OutgoingMultistreamSelectSession.PROTO_SECIO)) {
				try {
					// Do the secio stuff..
					LinkedList packets = secio.processServer(in, out, mykeys);
					System.out.println("In packets " + packets.size());
				} catch(SecioException se) {
					System.err.println("SecioException " + se);	
				}
			}
			sent_secio_starter = true;
			// TODO: Data processing goes here...
		}		
	}

	public void closing() {
	}
}