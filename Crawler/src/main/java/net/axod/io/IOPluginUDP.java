package net.axod.io;

import java.net.*;
import java.nio.*;
/**
 * This deals with UDP messages
 *
 * @author Jimmy Moore
 */

public abstract class IOPluginUDP {
    protected IOCore io;        // -> IOCore so we can send messages
    
    /**
     * Process a single UDP packet
     *
     */
    public abstract void processPacket(InetSocketAddress src, InetAddress dest, int destPort, ByteBuffer data, int n);
    
    /**
     * This gets called periodically
     *
     */
    public abstract void periodicProcess();
}
