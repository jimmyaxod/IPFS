package net.axod.ipfscrawl;

import net.axod.io.*;

import java.nio.*;
import java.net.*;

public class IPFSIOPluginIn extends IOPlugin {

	public IPFSIOPluginIn(Node n, InetSocketAddress isa) {
		System.out.println("INCOMING CONNECTION " + n + " on " + isa);
	}

	public boolean wantsToWork() {
		return false;	
	}

	public void work() {
	}

	public void closing() {
	}
}