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

    private boolean handshaked = false;
    private boolean recv_multistream = false;
    private String recv_protocol = null;

    public String getProtocol() {
    	return recv_protocol;	
    }
    
    public void reset() {
    	handshaked = false;
    	recv_multistream = false;
    	recv_protocol = null;
    }
    
	/**
	 * Process a multistream select
	 * IN 'multistream'
	 * IN 'protocol'
	 * OUT 'multistream'
	 * OUT 'protocol'		or 'na'
	 *
	 * @param	in	Input buffer
	 * @param	out	An output buffer we can write to
	 *
	 * @return	'protocol' when multistream handshake has half completed
	 */
	public String process(ByteBuffer in, ByteBuffer out) {
		if (!handshaked) {
			in.flip();
			while(in.remaining()>0) {
				// We haven't performed the multistream handshake yet, so we should do that now.
				
				// Try to read a complete packet. If we can't we abort so we can try later.
				try {
					String l = OutgoingMultistreamSelectSession.readMultistream(in);
					
					// Move forward...
					in.compact();
					in.flip();
					
					if (recv_multistream) {
						// We have a proposed protocol...
						recv_protocol = l;
						break;
					}
					
					// For now, we only support multistream/1.0.0
					if (l.equals(OutgoingMultistreamSelectSession.MULTISTREAM)) {
						// OK, as expected, lets progress...
						OutgoingMultistreamSelectSession.writeMultistream(out, OutgoingMultistreamSelectSession.MULTISTREAM);
						recv_multistream = true;
					}				
				} catch(BufferUnderflowException bue) {
					in.rewind();	// Partial packet. We'll try and read again later...
					break;
				}
			}
			in.compact();
		}
		return recv_protocol;
	}

	public boolean hasHandshaked() {
		return handshaked;	
	}
	
    public void sendAccept(ByteBuffer out) {
		OutgoingMultistreamSelectSession.writeMultistream(out, recv_protocol);
		handshaked = true;
    }
    
    public void sendReject(ByteBuffer out) {
		OutgoingMultistreamSelectSession.writeMultistream(out, OutgoingMultistreamSelectSession.PROTO_NA);
		handshaked = true;
    }
} 