package net.axod.ipfscrawl;

import net.axod.io.*;

import java.net.*;

public class IPFSIOPluginFactoryIn implements IOPluginFactory {
	
	public IPFSIOPluginFactoryIn() {
	}
	
	public IOPlugin getIOPlugin(Node node, InetSocketAddress isa) {
		return new IPFSIOPluginIn(node, isa);	
	}
}