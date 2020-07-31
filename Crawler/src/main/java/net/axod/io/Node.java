package net.axod.io;
import java.net.*;
import java.util.*;

/**
 * This is a single point we connect to with the IOCore.
 *
 * @author Jimmy Moore
 */

public class Node {
    protected InetSocketAddress isa;
    public HashMap properties = new HashMap();
    
    /**
     * Create a Node to connect to
     *
     */
    public Node(InetSocketAddress isa) {
        this.isa = isa;    
    }

    /**
     * Get the InetSocketAddress
     *
     */
    public InetSocketAddress getInetSocketAddress() {
        return isa;
    }

    /**
     * Set the address
     *
     */
    public void setInetSocketAddress(InetSocketAddress i) {
        isa = i;
    }
    
    /**
     * Show as a string
     *
     */
    public String toString() {
        return "Node isa:" + isa.toString();
    }
}
