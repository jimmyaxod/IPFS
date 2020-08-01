package net.axod.ipfscrawl;

import net.axod.io.*;

import java.net.*;

public class IPFSIOPluginFactory implements IOPluginFactory {
	public String host;
	
	public IPFSIOPluginFactory(String h) {
		host = h;	
	}
	
	public IOPlugin getIOPlugin(Node node, InetSocketAddress isa) {
		node.properties.put("host", host);
		return new IPFSIOPlugin(node, isa);	
	}
}