package net.axod.ipfscrawl;

import net.axod.io.*;
import net.axod.util.*;
import net.axod.measurement.*;
import net.axod.protocols.plugins.*;

import java.net.*;
import java.util.*;
import java.util.logging.*;

import io.ipfs.multiaddr.*;

/**
 * Simple tool to play around with the IPFS network
 *
 *
 */
public class Crawl implements IOCoreListener {
    private static Logger logger = Logger.getLogger("net.axod.ipfscrawl");
	private static IOCore io;
	private static long lastStatus = System.currentTimeMillis();
	private static long PERIOD_STATUS = 5000;

	public static FileOutputUtils outputs = new FileOutputUtils();
	
	// Max io size
	private static int max_size = 100;
	
	/**
	 * Start a crawl
	 *
	 */
	public static void main(String[] args) {
		try {
			outputs.FILE_DIR = "logs/";
			outputs.DO_FLUSHES = true;

			logger.info("Setting up an IOCore");
			io = new IOCore(new Crawl());		// IOCoreListener

			for(int i=0;i<args.length;i++) {
				if (args[i].equals("--help")) {
					System.out.println(" --dest <host> <port>");
					System.out.println(" --listen <host> <port>");
					System.out.println(" --max <num>");
					System.out.println(" --logs <dir>");
					System.exit(0);
				} else if (args[i].equals("--logs")) {
					i++;
					outputs.FILE_DIR = args[i] + "/";
				} else if (args[i].equals("--max")) {
					i++;
					max_size = Integer.parseInt(args[i]);
				} else if (args[i].equals("--dest")) {
					i++;
					String host = args[i];
					i++;
					int port = Integer.parseInt(args[i]);
					try {
						Node dest = new Node(new InetSocketAddress(host, port));
						dest.properties.put("host", host);
						logger.info("Attempting connection to " + dest + "...");

						IOPluginFactory iof = new IPFSIOPluginFactory();
						boolean suc = io.addConnection(dest, iof, null);
					} catch(Exception e) {
						logger.warning("Exception setting up connect " + e);	
					}
				} else if (args[i].equals("--listen")) {
					// Setup a listener on the given host / port...
					i++;
					String host = args[i];
					i++;
					int port = Integer.parseInt(args[i]);
					try {
						InetSocketAddress isa = new InetSocketAddress(host, port);
						IOPluginFactory iof = new IPFSIOPluginFactoryIn();
						io.addListen(isa, iof);
						
						// We will also add this to our identify packet
						IdentifyPlugin.registerListen(host, port);
					} catch(Exception e) {
						logger.warning("Exception setting up listen " + e);	
					}
				}
			}

			// =================================================================
			// Make a main status loop...
			//
			while(true) {
				if (System.currentTimeMillis() - lastStatus > PERIOD_STATUS) {
					logger.info("STATUS " + io);
					logger.info("STATUS currentConnectedHosts " + currentConnectedHosts.size() + " recentConnectedHosts " + recentConnectedHosts.size());
					DHTMetrics.showStatus();
					Timing.showTimings();
					
					// Check for issues watchdog
					// This checks on the IO thread to see if it's stalled for some reason.
					if (io.msSinceSelect() > 10) {
						// Get a stack trace...
						logger.warning("### IO ### Thread ### issue ###");
						
						StackTraceElement[] stackTrace = io.getStackTrace();
					   
						//Once you get StackTraceElement you can also print it to console
						System.err.println("displaying Stack trace from StackTraceElement in Java");
						for(StackTraceElement st : stackTrace){
						    System.err.println(st);
						}
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
	public static long RECENT_CONNECTED_TIME = 30000;
	public static long RECENT_CONNECTED_EXPIRE_CHECK = 5000;
	// host -> time
	// Keep track of current connected hosts
	public static HashSet currentConnectedHosts = new HashSet();

	public static void registerConnection(String host) {
		currentConnectedHosts.add(host);
	}

	public static void unregisterConnection(String host) {
		currentConnectedHosts.remove(host);	
		// Put it in recent for a while...
		recentConnectedHosts.put(host, new Long(System.currentTimeMillis()));
		
		long now = System.currentTimeMillis();
		if (now - lastExpireTime > RECENT_CONNECTED_EXPIRE_CHECK) {
			lastExpireTime = now;
			Iterator i = recentConnectedHosts.keySet().iterator();
			while(i.hasNext()) {
				String h = (String)i.next();
				long t = ((Long)recentConnectedHosts.get(h)).longValue();
				if ((now - t) > RECENT_CONNECTED_TIME) {
					i.remove();				// Expire it	
				}
			}
		}
	}

	/**
	 * Add a new connection to the given address
	 *
	 */
	public static void addConnection(MultiAddress ma) {
		// For now, we're only doing TCP connections
		if (!ma.isTCPIP()) return;

		// If we already have enough, drop it.
		if (currentConnectedHosts.size() > max_size) return;

		String host = ma.getHost();
		int port = ma.getTCPPort();
		try {
			// We are already connected to the host
			if (currentConnectedHosts.contains(host)) {
				return;
			}
			
			// We've recently been connected to the host
			if (recentConnectedHosts.containsKey(host)) {
				return;
			}
	
			InetSocketAddress isa = new InetSocketAddress(host, port);
			
			// Ignore local addresses (LAN etc).
			if (isa.getAddress().isSiteLocalAddress()) {
				return;
			}

			currentConnectedHosts.add(host);				// Put it in here...
			
			Node dest = new Node(isa);
			dest.properties.put("host", host);
			logger.fine("Attempting connection to " + dest + "...");
	
			IOPluginFactory iof = new IPFSIOPluginFactory();
			boolean suc = io.addConnection(dest, iof, null);
			if (!suc) {
				unregisterConnection(host);	
			}
		} catch(Exception e) {
			System.err.println("Connect failed " + host + " port " + port);
			e.printStackTrace();
			unregisterConnection(host);	
		}
	}

	/**
	 * The IOCore calls back to us here to tell us if connects were successful
	 * or not.
	 */
    public void connectionCallback(Node n, boolean success) {
    	long now = System.currentTimeMillis();
    	// Write to connectivity log...
    	outputs.writeFile("connectivity", now + "," + n.getInetSocketAddress().getAddress().getHostAddress() + "," + n.getInetSocketAddress().getPort() + "," + success + "\n");
    	
    	String host = (String)n.properties.get("host");
    	if (!success) {
    		unregisterConnection(host);
    	}
    }
	
}