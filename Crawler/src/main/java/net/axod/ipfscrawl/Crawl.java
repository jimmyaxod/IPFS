package net.axod.ipfscrawl;

import net.axod.io.*;
import net.axod.util.*;
import net.axod.measurement.*;

import java.net.*;
import java.util.*;
import java.util.logging.*;

import io.ipfs.multiaddr.*;

/**
 * Simple tool to play around with IPFS
 *
 *
 */

public class Crawl implements IOCoreListener {
    private static Logger logger = Logger.getLogger("net.axod.ipfscrawl");
	private static IOCore io;
	private static long lastStatus = System.currentTimeMillis();
	private static long PERIOD_STATUS = 5000;
	
	public static FileOutputUtils outputs = new FileOutputUtils();
	
	public static HashSet currentConnectedHosts = new HashSet();
	
	private static int max_size = 100;
	
	/**
	 *
	 *
	 */
	public static void main(String[] args) {
		try {
			outputs.FILE_DIR = "logs/";
			outputs.DO_FLUSHES = true;

			logger.info("Setting up an IOCore");

			io = new IOCore(new Crawl());		// IOCoreListener

			// Try an outgoing connection...

			for(int i=0;i<args.length;i++) {
				if (args[i].equals("--max")) {
					i++;
					max_size = Integer.parseInt(args[i]);
				} else if (args[i].equals("--dest")) {
					i++;
					String host = args[i];
					i++;
					int port = Integer.parseInt(args[i]);
					Node dest = new Node(new InetSocketAddress(host, port));
					dest.properties.put("host", "127.0.0.1");
					logger.info("Attempting connection to " + dest + "...");
		
					IOPluginFactory iof = new IPFSIOPluginFactory();
					boolean suc = io.addConnection(dest, iof, null);
					System.out.println("connection ok? " + suc);
				}
			}

			// Make a main status loop...
			while(true) {
				if (System.currentTimeMillis() - lastStatus > PERIOD_STATUS) {
					logger.info("STATUS " + io);
					logger.info("STATUS currentConnectedHosts " + currentConnectedHosts.size() + " recentConnectedHosts " + recentConnectedHosts.size());
					DHTMetrics.showStatus();
					Timing.showTimings();
					
					// Check for issues watchdog
					if (io.msSinceSelect() > 10) {
						// Get a stack trace...
						logger.warning("### IO ### Thread ### issue ###");
						
						StackTraceElement[] stackTrace = io.getStackTrace();
					   
						//Once you get StackTraceElement you can also print it to console
						System.err.println("displaying Stack trace from StackTraceElement in Java");
						for(StackTraceElement st : stackTrace){
						    System.err.println(st);
						}
//						io.dumpStack();
					}
					
					lastStatus = System.currentTimeMillis();
				} else {
					Thread.currentThread().sleep(1000);	
				}
			}

		} catch(Exception e) {
			logger.warning("Exception in main " + e);	
		}
	}

	public static long lastExpireTime = 0;
	public static HashMap recentConnectedHosts = new HashMap();
	// host -> time

	public static void registerConnection(String host) {
		currentConnectedHosts.add(host);
	}
	
	public static void unregisterConnection(String host) {
		currentConnectedHosts.remove(host);	
		// Put it in recent for a while...
		recentConnectedHosts.put(host, new Long(System.currentTimeMillis()));
		
		long now = System.currentTimeMillis();
		if (now - lastExpireTime > 5000) {
			lastExpireTime = now;
			Iterator i = recentConnectedHosts.keySet().iterator();
			while(i.hasNext()) {
				String h = (String)i.next();
				long t = ((Long)recentConnectedHosts.get(h)).longValue();
				if (now - t > 30000) {
					i.remove();				// Expire it	
				}
			}
		}
	}

	public static void addConnection(MultiAddress ma) {
		if (currentConnectedHosts.size()>max_size) return;		// 500 max for now

		if (!ma.isTCPIP()) return;
		String host = ma.getHost();

//			if (host.indexOf(":")!=-1) return;	// Don't care about ipv6 for now
		int port = ma.getTCPPort();

		try {
			
			if (currentConnectedHosts.contains(host)) {
				return;
			}
			
			if (recentConnectedHosts.containsKey(host)) {
				// Don't bother
				return;
			}
			currentConnectedHosts.add(host);				// Put it in here...
	
			Node dest = new Node(new InetSocketAddress(host, port));
			dest.properties.put("host", host);
			logger.fine("Attempting connection to " + dest + "...");
	
			IOPluginFactory iof = new IPFSIOPluginFactory();
			boolean suc = io.addConnection(dest, iof, null);
			if (!suc) {
				unregisterConnection(host);	
			}
			//System.out.println("connection ok? " + suc);
		} catch(Exception e) {
			System.err.println("Connect failed " + host + " port " + port);
			e.printStackTrace();
			unregisterConnection(host);	
		}
	}

    public void connectionCallback(Node n, boolean success) {
    	String host = (String)n.properties.get("host");
//    	System.out.println("connectionCallback " + n + " host " + host + " " + success);
    	if (!success) {
    		unregisterConnection(host);
    	}
    }
	
}