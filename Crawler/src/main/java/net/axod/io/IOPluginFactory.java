package net.axod.io;

import java.io.*;
import java.net.*;

/**
 * Create IOPlugins like this
 *
 */
 
public interface IOPluginFactory {
    
    /**
     * Create an IOPlugin
     *
     */
    public IOPlugin getIOPlugin(Node node, InetSocketAddress isa);
}
