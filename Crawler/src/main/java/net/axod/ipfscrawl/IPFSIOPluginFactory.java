package net.axod.ipfscrawl;

import net.axod.io.*;

import java.net.*;

/**
 * This gives us a way to create new IPFSIOPlugins...
 *
 */
public class IPFSIOPluginFactory implements IOPluginFactory {
	
	public IPFSIOPluginFactory() {
	}
	
	public IOPlugin getIOPlugin(Node node, InetSocketAddress isa) {
		return new IPFSIOPlugin(node, isa);	
	}
}