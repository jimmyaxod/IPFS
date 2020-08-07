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
    private boolean sent_multistream = false;
    private boolean recv_multistream = false;
    private String recv_protocol = null;

	/**
	 * Process a multistream select
	 * OUT 'multistream'
	 * IN 'multistream'
	 * IN 'protocol'
	 * OUT 'protocol'		or 'na'
	 *
	 * @param	in	Input buffer
	 * @param	out	An output buffer we can write to
	 *
	 * @return	'protocol' when multistream handshake has half completed
	 */
	public String process(ByteBuffer in, ByteBuffer out) {
		if (!handshaked) {
			if (!sent_multistream) {
				OutgoingMultistreamSelectSession.writeMultistream(out, OutgoingMultistreamSelectSession.MULTISTREAM);
				sent_multistream = true;
			}

			// We haven't performed the multistream handshake yet, so we should do that now.
			in.flip();
			
			// Try to read a complete packet. If we can't we abort so we can try later.
			try {
				String l = OutgoingMultistreamSelectSession.readMultistream(in);	
				logger.fine("Multistream handshake (" + l.trim() + ")");

				// For now, we only support multistream/1.0.0
				if (l.equals(OutgoingMultistreamSelectSession.MULTISTREAM)) {
					// OK, as expected, lets progress...
					recv_multistream = true;
				}
				
				if (recv_multistream) {
					// We have a proposed protocol...
					recv_protocol = l;
				}
			} catch(BufferUnderflowException bue) {
				in.rewind();	// Partial packet. We'll try and read again later...
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