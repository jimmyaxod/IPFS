package net.axod.protocols;

import java.nio.*;
import java.util.logging.*;

/**
 * This knows about multistream
 * It can read and write
 *
 */
 
public class Multistream {
    private static Logger logger = Logger.getLogger("net.axod.protocols");
	public final static String MULTISTREAM = "/multistream/1.0.0\n";

	public final static String PROTO_SECIO = "/secio/1.0.0\n";
	public final static String PROTO_YAMUX = "/yamux/1.0.0\n";

	public String proto = null;
	public boolean handshaked = false;
	
	/**
	 * Setup a new multistream
	 *
	 */
	public Multistream(String proto) {
		this.proto = proto;
	}
	
	/**
	 * Process a multistream select
	 *
	 */
	public boolean process(ByteBuffer in, ByteBuffer out) {
		if (!handshaked) {
			// We haven't performed the multistream handshake yet, so we should do that now.
			in.flip();
			
			System.out.println("in remaining " + in.remaining());
			
			// Try to read a complete packet. If we can't we abort so we can try later.
			try {
				String l = readMultistream(in);	
				logger.info("Multistream handshake (" + l.trim() + ")");

				// For now, we only support multistream/1.0.0
				if (l.equals(MULTISTREAM)) {
					// OK, as expected, lets reply and progress...
					writeMultistream(out, MULTISTREAM);						
					writeMultistream(out, proto);

				// For now, we only support secio/1.0.0
				} else if (l.equals(proto)) {
					// OK, need to move on to next stage now...
					handshaked = true;
					logger.info("Switching to " + proto);
				}
			} catch(BufferUnderflowException bue) {
				in.rewind();	// Partial packet. We'll try and read again later...
			}
			in.compact();
		}
		return handshaked;		
	}
	
	public static void writeMultistream(ByteBuffer dest, String data) {
		byte[] d = data.getBytes();
		writeVarInt(dest, d.length);
		dest.put(d);
	}

	public static String readMultistream(ByteBuffer src) {
		long len = readVarInt(src);
		byte[] data = new byte[(int)len];
		src.get(data);
		return new String(data);
	}

	public static void writeVarInt(ByteBuffer oo, long v) {
		while(true) {
			byte d = (byte)(v & 0x7f);
			if (v>0x80) {
				d = (byte) (d | 0x80);	// Signal there's more to come...
				oo.put(d);
			} else {
				oo.put(d);
				break;
			}
			v = v >> 7;
		}
	}

	public static long readVarInt(ByteBuffer bb) throws BufferUnderflowException {
		long len = 0;
		int sh = 0;
		while(true) {
			int b = ((int)bb.get()) & 0xff;
			long v = (b & 0x7f);
			len = len | (v << sh);
			if ((b & 0x80)==0) break;
			sh+=7;
		}
		return len;			
	}
}