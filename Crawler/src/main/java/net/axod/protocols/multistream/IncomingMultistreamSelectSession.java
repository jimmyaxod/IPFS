package net.axod.protocols.multistream;

import java.nio.*;
import java.util.logging.*;

/**
 * This knows about multistream
 * It can read and write messages, and you can use the process to handle a
 * handshake.
 *
 *
 */

public class IncomingMultistreamSelectSession {
    private static Logger logger = Logger.getLogger("net.axod.protocols");

    
    // For incoming connections, we need to negotiate, but also decide
    // whether we support the required protocol.
    // if not, we should return with 'na'
    
}                             