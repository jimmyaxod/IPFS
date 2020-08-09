package net.axod.ipfscrawl;

import net.axod.io.*;
import net.axod.ipfscrawl.*;
import net.axod.protocols.multistream.*;

import java.nio.*;
import java.net.*;
import java.util.logging.*;

public class IPFSIOPluginIn extends IOPlugin {
	IncomingMultistreamSelectSession multi = new IncomingMultistreamSelectSession();

	public IPFSIOPluginIn(Node n, InetSocketAddress isa) {
		System.out.println("INCOMING CONNECTION " + n + " on " + isa);
	}

	public boolean wantsToWork() {
		return false;
	}

	public void work() {
		long now = System.currentTimeMillis();

		if (!multi.hasHandshaked()) {
			String proto = multi.process(in, out);
			if (proto!=null) {				
				// For now, log it...
				Crawl.outputs.writeFile("in_connect_protocols", now + "," + proto.trim() + "\n");
				
				close();
				return;
			}
		} else {
			// TODO: Data processing goes here...
		}		
	}

	public void closing() {
	}
}