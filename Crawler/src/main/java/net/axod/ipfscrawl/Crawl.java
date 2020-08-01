package net.axod.ipfscrawl;

import net.axod.io.*;
import net.axod.util.*;

import java.net.*;
import java.util.*;
import java.util.logging.*;

import io.ipfs.multiaddr.*;

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
	
	public static FileOutputUtils outputs = new FileOutputUtils();
	
	public static HashSet currentConnectedHosts = new HashSet();
	
	
	/**
	 *
	 *
	 */
	public static void main(String[] args) {
		try {
			outputs.FILE_DIR = "logs/";
			outputs.DO_FLUSHES = true;

			logger.info("Setting up an IOCore");

			io = new IOCore();

			// Try an outgoing connection...
	
			Node dest = new Node(new InetSocketAddress("127.0.0.1", 4001));
			logger.info("Attempting connection to " + dest + "...");

			IOPluginFactory iof = new IPFSIOPluginFactory("127.0.0.1");
			boolean suc = io.addConnection(dest, iof, null);
			System.out.println("connection ok? " + suc);

			// Make a main status loop...
			while(true) {
				if (System.currentTimeMillis() - lastStatus > PERIOD_STATUS) {
					logger.info("STATUS " + io);
					logger.info("STATUS currentConnectedHosts " + currentConnectedHosts.size());
					lastStatus = System.currentTimeMillis();
				} else {
					Thread.currentThread().sleep(1000);	
				}
			}

		} catch(Exception e) {
			logger.warning("Exception in main " + e);	
		}
	}

	public static void registerConnection(String host) {
		currentConnectedHosts.add(host);
	}
	public static void unregisterConnection(String host) {
		currentConnectedHosts.remove(host);	
	}
	
	public static void addConnection(MultiAddress ma) {
		if (!ma.isTCPIP()) return;
		try {
			String host = ma.getHost();
			int port = ma.getTCPPort();
			
			if (currentConnectedHosts.contains(host)) {
				// Don't bother
				return;
			}
	
			Node dest = new Node(new InetSocketAddress(host, port));
			logger.info("Attempting connection to " + dest + "...");
	
			IOPluginFactory iof = new IPFSIOPluginFactory(host);
			boolean suc = io.addConnection(dest, iof, null);
			System.out.println("connection ok? " + suc);
		} catch(Exception e) {
			System.err.println("Connect failed");	
		}
	}
	
}