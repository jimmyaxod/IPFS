package net.axod.io;
import java.nio.*;
import java.io.*;
import java.net.*;

/**
 * The basic IOPlugin for all network plugins
 *
 * @author Jimmy Moore
 */

public abstract class IOPlugin {
    private static int DEFAULT_IN_SIZE = 130*1024;
    private static int DEFAULT_OUT_SIZE = 8*1024;
    protected IOCore ioCore = null;
    public ByteBuffer in = null;
    public ByteBuffer out = null;

    /**
     * Create an IOPlugin with default sizes
     *
     */
    public IOPlugin() {
        this(DEFAULT_IN_SIZE, DEFAULT_OUT_SIZE);
    }

    /**
     * Create an IOPlugin
     *
     */
    public IOPlugin(int sizeIn, int sizeOut) {
        in = ByteBuffer.allocate(sizeIn);
        out = ByteBuffer.allocate(sizeOut);
    }
    
    /**
     * Ask the plugin if it needs to do something
     *
     */
    public abstract boolean wantsToWork();

    /**
     * Allow the plugin to do things
     *
     */
    public abstract void work();

    /**
     * Tell the plugin it is closing
     *
     */
    public abstract void closing();

    /**
     * Callback from the plugin to request it be closed
     *
     */
    public void close() {
        if (ioCore!=null) ioCore.close(this);
    }
}
