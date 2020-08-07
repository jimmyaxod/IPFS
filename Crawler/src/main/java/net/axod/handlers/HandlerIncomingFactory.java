package net.axod.handlers;

import net.axod.io.*;

import java.net.*;

public class HandlerIncomingFactory implements IOPluginFactory {
	
    public IOPlugin getIOPlugin(Node node, InetSocketAddress isa) {
    	return new HandlerIncoming();	
    }
}