package net.axod.ipfscrawl;

import net.axod.io.*;

import java.net.*;
import java.util.logging.*;

/**
 * Simple tool to play around with IPFS
 *
 *
 */

public class Crawl {
    private static Logger logger = Logger.getLogger("net.axod.ipfscrawl");
	private static IOCore io;
	private static long lastStatus = System.currentTimeMillis();
	private static long PERIOD_STATUS = 5000;
	
	/**
	 *
	 *
	 */
	public static void main(String[] args) {
		try {
			logger.info("Setting up an IOCore");

			io = new IOCore();

			// Try an outgoing connection...
	
			Node dest = new Node(new InetSocketAddress("127.0.0.1", 4001));
			logger.info("Attempting connection to " + dest + "...");

			IOPluginFactory iof = new IPFSIOPluginFactory();
			boolean suc = io.addConnection(dest, iof, null);
			System.out.println("connection ok? " + suc);

			// Make a main status loop...
			while(true) {
				if (System.currentTimeMillis() - lastStatus > PERIOD_STATUS) {
					logger.info("STATUS " + io);
					lastStatus = System.currentTimeMillis();
				} else {
					Thread.currentThread().sleep(1000);	
				}
			}

		} catch(Exception e) {
			logger.warning("Exception in main " + e);	
		}
	}

}