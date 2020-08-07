package net.axod.handlers;

import net.axod.io.*;
import net.axod.protocols.multistream.*;

import java.nio.*;

public class HandlerIncoming extends IOPlugin {

	IncomingMultistreamSelectSession multi = new IncomingMultistreamSelectSession();
	
	public boolean wantsToWork() {
		return false;
	}

	public void work() {
		String proto = multi.process(in, out);
		if (proto!=null) {
			System.out.println("INCOMING [" + proto + "]");
			multi.sendReject(out);
			multi.reset();
		}
	}

	public void closing() {
		
	}
}