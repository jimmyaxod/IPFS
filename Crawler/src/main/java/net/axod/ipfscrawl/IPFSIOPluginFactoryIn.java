package net.axod.ipfscrawl;

import net.axod.io.*;

import java.net.*;

/**
 * Gives us a way to create new IPFSIOPluginIn
 * This is for incoming TCP Connections.
 *
 */
public class IPFSIOPluginFactoryIn implements IOPluginFactory {
	
	public IPFSIOPluginFactoryIn() {
	}
	
	public IOPlugin getIOPlugin(Node node, InetSocketAddress isa) {
		return new IPFSIOPluginIn(node, isa);	
	}
}