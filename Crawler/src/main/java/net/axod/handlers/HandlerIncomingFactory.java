package net.axod.handlers;

import net.axod.io.*;
import net.axod.ipfscrawl.*;

import java.net.*;

public class HandlerIncomingFactory implements IOPluginFactory {
	IPFSIOPlugin iop = null;
	
	public HandlerIncomingFactory(IPFSIOPlugin i) {
		iop = i;	
	}
	
    public IOPlugin getIOPlugin(Node node, InetSocketAddress isa) {
    	return new HandlerIncoming(iop);	
    }
}