package net.axod.io;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;

/**
 * This is the info associated with a TCP connection
 *
 */
 
public class IOConnectInfo {
    protected SocketChannel socketChannel;
    protected SelectionKey selectionKey;
    protected IOPluginFactory ioPluginFactory;
    protected IOPlugin ioPlugin;
    protected Node node;

    /**
     * Create an IOConnectInfo
     *
     */
    public IOConnectInfo(IOPluginFactory plug, SocketChannel s, SelectionKey sk, Node n) {
        socketChannel = s;
        selectionKey = sk;
        ioPluginFactory = plug;
        node = n;
    }
    
    /**
     * Create the IOPlugin
     *
     */
    public IOPlugin getIOPlugin() {
        InetSocketAddress l = new InetSocketAddress(socketChannel.socket().getLocalAddress(), socketChannel.socket().getLocalPort()); 
        ioPlugin = ioPluginFactory.getIOPlugin(node, l);
        return ioPlugin;
    }

    /**
     * Show as a string
     *
     */
    public String toString() {
        return "IOConnectInfo IOPF:" + ioPluginFactory
        + ", IOP:" + ioPlugin + ", SC:" + socketChannel
        + ", SK:" + selectionKey + ", node:" + node;
    }
}
