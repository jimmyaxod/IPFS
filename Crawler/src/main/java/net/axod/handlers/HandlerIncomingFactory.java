package net.axod.handlers;

import net.axod.io.*;
import net.axod.ipfscrawl.*;

import java.net.*;

public class HandlerIncomingFactory implements IOPluginFactory {
	ClientDetails client = null;
	
	public HandlerIncomingFactory(ClientDetails i) {
		client = i;	
	}
	
    public IOPlugin getIOPlugin(Node node, InetSocketAddress isa) {
    	return new HandlerIncoming(client);
    }
}