package net.axod.io;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import java.util.logging.*;

/**
 * IOCore - this handles all networking
 *
 * @author Jimmy Moore
 */
public class IOCore extends Thread {
    private static Logger logger = Logger.getLogger("com.medialabs.io");
    private int MAX_SELECTOR_SIZE = 100000;
    private long SERVICE_PERIOD = 250;
    private long SELECT_TIMEOUT = 200;
    private int ACCEPT_BACKLOG = 100;
    private long NO_NET_SLEEP = 100;
	private int MAX_UDP_PACKETS_PROCESS = 250;
	private boolean CLEAR_EXCESS_UDP_PACKETS = true;

    private long total_selects = 0;

	private long udp_sent = 0;
	private long udp_send_failed = 0;
	private long udp_recv = 0;
	private long total_discarded_udp_packets = 0;
	
	private long totalTimeUDPProcessPacket = 0;

    private Vector pendingCloses = new Vector();
    private HashMap connections = new HashMap();
    private HashMap listeners = new HashMap();
    private HashMap listenerUDPs = new HashMap();
    private HashMap senderUDPs = new HashMap();

    private Selector selector;
    private boolean running = true;

    private long serviceLastTime = 0;

	private long lastSelectTime = 0;
    
    private IOCoreListener callback = null;
    
    /**
     * Create a new IOCore
     *
     */
    public IOCore() throws IOException {
        selector = Selector.open();
        this.start();
    }
    
    public IOCore(IOCoreListener l) throws IOException {
        this();
        callback = l;
    }

    /**
     * Request the IOCore shuts down
     *
     */
    public void shutDown() {
        running = false;
    }
    
    /**
     * Check if the IOCore is empty
     *
     */
    public boolean isEmpty() {
        return (size()==0);
    }
    
    /**
     * Get the size of this
     *
     */
    public int size() {
        synchronized(selector) {
            return selector.keys().size();
        }
    }
    
    /**
     * Show as a string
     *
     */
    public String toString() {
		long dt = (System.currentTimeMillis() - lastSelectTime) / 1000;
        return "IOCore: since_select=" + dt + " size=" + size() + " connections=" + connections.size() + " selects=" + total_selects + " udp S=" + udp_sent + " (" + udp_send_failed + " failed) R=" + udp_recv + " Discarded=" + total_discarded_udp_packets + " totalTimeUDPProcessPacket=" + totalTimeUDPProcessPacket;
    }

    /**
     * This is the main run method
     *
     */
    public void run() {
        while(running) {
            long now = System.currentTimeMillis();
            
            processPendingCloses();

            if (now - serviceLastTime > SERVICE_PERIOD) {
                serviceLastTime = now;
                serviceConnections();
            }
            
            processPendingCloses();

            Set s = selector.keys();

            if (s.size() > 0) {
                try {
                    Set t = null;
                    synchronized(selector) {

                    	// Show current selected keys size...

                        int n = selector.select(SELECT_TIMEOUT);
						total_selects++;
						lastSelectTime = System.currentTimeMillis();
                        t = selector.selectedKeys();
/*
                        if (t.size()==0) {
                        	t = new HashSet();
                        	// Double check...	
							int totalReadable = 0;
							synchronized(selector) {
								Set allkeys = selector.keys();
								Iterator ii = allkeys.iterator();
								while(ii.hasNext()) {
									SelectionKey sk = (SelectionKey)ii.next();
									if ((sk.interestOps() & SelectionKey.OP_READ)!=0 && sk.isReadable()) {
										totalReadable++;
										t.add(sk);
									}
								}
							}

							if (totalReadable>0) System.err.println("OS_BUG? Total Readable = " + totalReadable);
                        }
*/
                    }
                    if (t.size() > 0) {
                        processSelected(t);
                    } else {
                        
                    	// Sleep a little...
                        try {
                            Thread.currentThread().sleep(NO_NET_SLEEP);
                        } catch(Exception e) {}

                    }
                } catch(Exception e) {
                    logger.logp(Level.WARNING, "IOCore", "run", "Exception", e);
                }
            } else {
                try {
                    Thread.currentThread().sleep(NO_NET_SLEEP);
                } catch(Exception e) {}
            }
        }
    }
    
    /**
     * Process selected
     *
     */
    private void processSelected(Set t) throws Exception {
        Iterator i = t.iterator();
        while(i.hasNext()) {
            SelectionKey selk = (SelectionKey) i.next();
            i.remove();

            try {
                if (selk.isValid()) {
                    if (selk.channel() instanceof SocketChannel) {
                        SocketChannel ssc = (SocketChannel) selk.channel();
                        
                        if (selk.isConnectable()) {
                            processConnect(selk, ssc);
                        }
                        
                        if (ssc.isConnected()) {
                            IOConnectInfo ci = (IOConnectInfo) selk.attachment();
                            
                            if (selk.isWritable()) {
                                processWrite(ci);
                            }
                            if (selk.isReadable()) {
                                processRead(ci);
                            }
                        }
                    } else if (selk.channel() instanceof ServerSocketChannel) {
                        ServerSocketChannel ssc = (ServerSocketChannel) selk.channel();

                        if (selk.isAcceptable()) {
                            processAccept(selk, ssc);
                        }
                    } else if (selk.channel() instanceof DatagramChannel){
                        processDatagramChannel(selk);
                    }
                } else {
                    logger.logp(Level.WARNING, "IOCore", "processSelected", "Invalid key! " + selk);
                }
            } catch (CancelledKeyException e) {
            }
        }
    }
    
    /**
     * Allow a plugin to do some work
     *
     */
    private void work(IOPlugin pl) {
        pl.work();
        updateWrite(pl);
    }
    
    /**
     * update the write flags if needed
     *
     */
    public void updateWrite(IOPlugin pl) {
        IOConnectInfo ci = (IOConnectInfo) connections.get(pl);
        if (ci==null) {
            logger.logp(Level.WARNING, "IOCore", "updateWrite", "Invalid pl! " + pl);
            return;
        }
        if (pl.out.position() > 0) {
            ci.selectionKey.interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
        } else {
            ci.selectionKey.interestOps(SelectionKey.OP_READ);
        }
    }

    /**
     * schedule a plugin to be closed
     *
     */
    public void close(IOPlugin pl) {
        if (!pendingCloses.contains(pl)) pendingCloses.add(pl);
    }
    
    /**
     * Close any pending closes
     *
     */
    public void processPendingCloses() {
        for (int i=0;i<pendingCloses.size();i++) {
            IOPlugin pl = (IOPlugin) pendingCloses.get(i);
            try {
                IOConnectInfo n = (IOConnectInfo) connections.get(pl);
                if (n==null) {
                    logger.logp(Level.INFO, "IOCore", "close", "IOPlugin not found!");
                } else {
                    n.socketChannel.close();
                    n.selectionKey.cancel();
                    n.selectionKey.attach(null);
                    pl.closing();
                    connections.remove(pl);
                }
            } catch(Exception e) {
                logger.logp(Level.INFO, "IOCore", "close", "Exception closing", e);            
            }
        }
        pendingCloses.clear();
    }

    /**
     * service plugins
     *
     */
    private void serviceConnections() {
        Iterator ai = connections.keySet().iterator();
        while(ai.hasNext()) {
            IOPlugin pl = (IOPlugin) ai.next();
            IOConnectInfo n = (IOConnectInfo) connections.get(pl);
            try {
                if (pl.wantsToWork()) work(pl);
            } catch(Throwable e) {
                logger.logp(Level.WARNING, "IOCore", "serviceConnections", "Throwable ", e);                        
                close(pl);
            }
        }
    }

    /**
     * process any connections
     *
     */
    private void processConnect(SelectionKey selk, SocketChannel ssc) {
        try {
            ssc.finishConnect();
            IOConnectInfo nci = (IOConnectInfo) selk.attachment();

            selk.interestOps(SelectionKey.OP_READ);
            IOPlugin iop = nci.getIOPlugin();
            iop.ioCore = this;
            connections.put(iop, nci);
            if (callback!=null) callback.connectionCallback(nci.node, true);            // Signal success!
            try {
                if (iop.wantsToWork()) work(iop);
            } catch(Throwable e) {
                logger.logp(Level.WARNING, "IOCore", "processConnect", "Throwable ", e);
                close(iop);
            }
        } catch (Exception ioe) {
            IOConnectInfo nci = (IOConnectInfo) selk.attachment();
            //logger.logp(Level.INFO, "IOCore", "processConnect", "Connect " + nci.node, ioe);
            
            try {
                if (callback!=null) callback.connectionCallback(nci.node, false);       // Signal epic failure
                ssc.close();
                selk.attach(null);
                selk.cancel();
            } catch(Exception ie) {
                logger.logp(Level.INFO, "IOCore", "processConnect", "Exception closing", ie);
            }
        }
    }

    /**
     * process any plugins that need writing
     *
     */
    private void processWrite(IOConnectInfo ci) {
        IOPlugin ia = null;
        try {
            ia = ci.ioPlugin;
            SocketChannel ssc = ci.socketChannel;
            if (ia.out.position() > 0) {
                ia.out.flip();
                int j = ssc.write(ia.out);
                ia.out.compact();
                updateWrite(ia); // Adjust if needed...
            }
        } catch (Exception e) {
            logger.logp(Level.FINE, "IOCore", "processWrite", "Exception", e);            
            if (ia!=null) close(ia);
        }
    }

    /**
     * process any plugins needing reading
     *
     */
    private void processRead(IOConnectInfo ci) {
        IOPlugin ia = null;
        try {
            ia = ci.ioPlugin;
            SocketChannel ssc = ci.socketChannel;
            int j = ssc.read(ia.in);
            if (j == -1) throw (new IOException("End of stream"));
        } catch(IOException e) {
            logger.logp(Level.FINE, "IOCore", "processRead", "Exception", e);
            if (ia!=null) close(ia);            
        }
        try {
            if (ia.in.position() > 0) work(ia);
        } catch (Throwable e) {
            logger.logp(Level.WARNING, "IOCore", "processRead", "Throwable ", e);
            if (ia!=null) close(ia);
        }
    }

    /**
     * process any plugins connecting to us
     *
     */
    private void processAccept(SelectionKey selk, ServerSocketChannel ssc) {
        int processed = 0;
        while(true) {
            try {
                SocketChannel so = ssc.accept();
                if (so==null) break;
                
                int max = MAX_SELECTOR_SIZE * 2;
                
                if (selector.keys().size() < max) {
                    so.configureBlocking(false);
                    IOPlugin f = null;
                    SelectionKey sk = null;
                    try {
                        IOPluginFactory iof = (IOPluginFactory) listeners.get(ssc);
                        synchronized(selector) {
                            sk = so.register(selector, SelectionKey.OP_READ);
                        }
                        InetSocketAddress isa = new InetSocketAddress(so.socket().getInetAddress(), so.socket().getPort());
                        InetSocketAddress lisa = new InetSocketAddress(so.socket().getLocalAddress(), so.socket().getLocalPort());
                        Node node = new Node(isa);
                        
                        IOConnectInfo ni = new IOConnectInfo(iof, so, sk, node);
                        f = ni.getIOPlugin();
                        f.ioCore = this;
                        sk.attach(ni);
                        connections.put(f, ni);
                        try {
                            if (f.wantsToWork()) work(f);
                        } catch(Throwable e) {
                            logger.logp(Level.WARNING, "IOCore", "processAccept", "Throwable ", e);
                            close(f);
                        }
                    } catch(Exception e) {
                        logger.logp(Level.INFO, "IOCore", "processAccept", "Error accepting", e);
                        if (sk!=null) {
                            sk.attach(null);
                            sk.cancel();
                        }
                        if (f!=null) close(f);    
                    }
                } else {
                    so.close();
                    break;
                }
            } catch(Exception e) {
                logger.logp(Level.WARNING, "IOCore", "processAccept", "Error accepting", e);
            }
        }
    }

    /**
     * Add a new connection
     *
     */
    public boolean addConnection(Node dest, IOPluginFactory iof, InetSocketAddress isa) throws IOException {

        synchronized(selector) {
            if (connections.size() >= MAX_SELECTOR_SIZE) return false;
    
            SocketChannel sc = null;
            SelectionKey sk = null;
            try {
                if (dest!=null) {
                    sc = SocketChannel.open();
                    sc.configureBlocking(false);
    
                    if (isa != null) sc.socket().bind(isa);
    
                    sk = sc.register(selector, SelectionKey.OP_CONNECT);
                    IOConnectInfo nci = new IOConnectInfo(iof, sc, sk, dest);
    
                    sk.attach(nci);
                    sc.connect(dest.isa);
                }
            } catch (IOException e) {
                if (sc!=null) sc.close();
                if (sk!=null) sk.cancel();
                throw(e);
            } catch (Exception e) {
                logger.logp(Level.INFO, "IOCore", "addConnection", "Exception adding connection to " + dest, e);
                if (sc!=null) sc.close();                 // Close the channel.
                if (sk!=null) sk.cancel();                // Cancel the selectionKey
                return false;
            }
            return true;
        }
    }

    /**
     * Add a listen
     *
     */
    public void addListen(InetSocketAddress local, IOPluginFactory iof) throws IOException {        
        synchronized(selector) {
            ServerSocketChannel ssc = ServerSocketChannel.open();
            ssc.configureBlocking(false);
            ssc.socket().bind(local, ACCEPT_BACKLOG);
            SelectionKey sk = ssc.register(selector, SelectionKey.OP_ACCEPT);
            listeners.put(ssc, iof);
        }
    }

    /**
     * Send a UDP packet
     *
     */
    public void sendUDP(InetSocketAddress local, InetSocketAddress remote, ByteBuffer data){
        DatagramChannel dc = (DatagramChannel)senderUDPs.get(local);

        if(dc != null){
            try {
                int n = dc.send(data, remote);
				udp_sent++;
				if (n==0) {
					udp_send_failed++;
//					System.err.println("No space to send UDP packet");
				}
            } catch(Exception e) {
                logger.logp(Level.FINE, "IOCore", "sendUDP", "Error sending " + local + " -> " + remote, e);
            }
        } else {
            logger.logp(Level.INFO, "IOCore", "sendUDP", "Error sending (dc==null) " + local);
        }
    }

    /**
     * Add a listen for UDP packets
     *
     */
    public void addListen(InetSocketAddress local, IOPluginUDP iop) throws IOException {
        try {
            DatagramChannel dc = DatagramChannel.open();
            dc.configureBlocking(false);
            dc.socket().bind(local);              // Bind it to the local address

            SelectionKey sk = dc.register(selector, SelectionKey.OP_READ);
            listenerUDPs.put(dc, iop);              // Save for later...
            senderUDPs.put(local, dc);              // Save for sending...
            iop.io = this;
        } catch(Exception e){
            logger.logp(Level.WARNING, "IOCore", "addListen(udp)", "Exception adding listen " + local, e);
        }
    }

    /**
     * Process any incomming UDP packets
     *
     */
    private void processDatagramChannel(SelectionKey selk){
        try {
            DatagramChannel dc = (DatagramChannel)selk.channel();
            if (selk.isReadable()) {

                int thisRunUDPCount = 0;
                InetSocketAddress src = null;
                IOPluginUDP iop = (IOPluginUDP)listenerUDPs.get(dc);
                ByteBuffer bu = ByteBuffer.allocate(65535);
				int i = 0;
				while(true) {
                    bu.clear();
                    src = (InetSocketAddress)dc.receive(bu);

                    if (i==0 && src==null) {
                    	System.err.println("Can't receive from dc port " + dc.socket().getLocalPort() + " " + bu);
                    }
                    
					if (i<MAX_UDP_PACKETS_PROCESS) {
	                    if(src!=null && iop!=null){
	                        try {
								udp_recv++;
								long ctime = System.currentTimeMillis();
	                            iop.processPacket(src, dc.socket().getLocalAddress(), dc.socket().getLocalPort(), bu, thisRunUDPCount++);
	                            totalTimeUDPProcessPacket+=(System.currentTimeMillis()-ctime);
	                        } catch(RuntimeException re){
	                            logger.logp(Level.WARNING, "IOCore", "processDatagramChannel", "RuntimeException ", re);
	                        }
	                    }
					} else if (!CLEAR_EXCESS_UDP_PACKETS) {
						break;
					} else if (CLEAR_EXCESS_UDP_PACKETS) {
						total_discarded_udp_packets++;
					}
					if (src==null) break;
					i++;
				}
            }
        } catch(Exception e) {
            logger.logp(Level.WARNING, "IOCore", "processDatagramChannel", "Exception reading datagram", e);
        }
    }

	/**
	 * Find out what the in/out buffers are doing...
	 *
	 */
//	public HashMap getUDPKernelBufferStats() {
		// Go through all listenerUDPs and compile the stats...
//	}

	// Example
	//
	//   sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  	//  27: 00000000000000000000000000000000:E81B 00000000000000000000000000000000:0000 07 00000000:000F41C2 00:00000000 00000000  1000        0 71496814 2 d7595d40

	/**
	 * This can be used to check if there's enough space in the kernel buffers to make it worth sending etc
	 *
	 */
	public int[] getUDPKernelBufferSizes(int p) {
		BufferedReader br = null;
		try {
			// We need to find the info for this
			br = new BufferedReader(new FileReader("/proc/net/udp6"));
			while(true) {
				String l = br.readLine();
				if (l==null) break;
				// Parse it if we can...
				String[] ls = l.trim().split(" +");

				if (ls.length>5) {
					String[] ladd = ls[1].trim().split(":");
					if (ladd.length>1 && Integer.parseInt(ladd[1], 16)==p) {
						// Extract the queues...
						String[] qs = ls[4].split(":");
						int[] result = new int[2];
						result[0] = Integer.parseInt(qs[0], 16);
						result[1] = Integer.parseInt(qs[1], 16);
						return result;
					}
				}
			}
		} catch(IOException e) {
			System.out.println("Cant check network buffers");
		} finally {
			if (br!=null) {
				try {br.close();} catch(IOException e) {}
			}
		}
		return null;
	}

	/**
	 * For a list of ports...
	 */
	public long[] getUDPKernelBufferSizes(HashSet ports) {
		BufferedReader br = null;
		long[] result = new long[2];
		result[0] = 0;
		result[1] = 0;

		boolean is_header = true;
		
		try {
			// We need to find the info for this
			br = new BufferedReader(new FileReader("/proc/net/udp6"));
			while(true) {
				String l = br.readLine();
				if (l==null) break;
				// Parse it if we can...
				String[] ls = l.trim().split(" +");		// Split on spaces.
				//   sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
				// 3222: 0000000000000000FFFF000012F0000A:1770 00000000000000000000000000000000:0000 07 00000000:000065C0 00:00000000 00000000  1000        0 1866130 2 0000000000000000 79
				// 3223: 0000000000000000FFFF000012F0000A:1771 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 1866131 2 0000000000000000 91

				if (is_header) {
					is_header = false;
				} else {
					if (ls.length>5) {
						String[] ladd = ls[1].trim().split(":");
						if (ladd.length>1 && ports.contains(Integer.toString(Integer.parseInt(ladd[1], 16)))) {
							// Extract the queues...
							String[] qs = ls[4].split(":");
							result[0] += Integer.parseInt(qs[0], 16);
							result[1] += Integer.parseInt(qs[1], 16);
						}
					}
				}
			}
		} catch(IOException e) {
			System.out.println("Cant check network buffers");
		} finally {
			if (br!=null) {
				try {br.close();} catch(IOException e) {}
			}
		}
		return result;
	}

}
