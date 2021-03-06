package net.axod.protocols.multistream;

import java.nio.*;
import java.util.logging.*;

/**
 * This knows about multistream
 * It can read and write messages, and you can use the process to handle a
 * handshake.
 *
 * eg for an outgoing connection:
 * multi_secio = new Multistream(Multistream.PROTO_SECIO);
 * ...
 * if (multi_secio.process(in, out)) {
 *     //do next thing inside secio
 *
 *
 * TODO: Handle downgrading. eg try noise, if unavailable try secio.
 */

public class OutgoingMultistreamSelectSession {
    private static Logger logger = Logger.getLogger("net.axod.protocols");
	public final static String MULTISTREAM = "/multistream/1.0.0\n";

	public final static String PROTO_NA = "na\n";
	// Crypto
	public final static String PROTO_SECIO = "/secio/1.0.0\n";
	public final static String PROTO_NOISE = "/noise\n";
	
	// Mux
	public final static String PROTO_YAMUX = "/yamux/1.0.0\n";

	// IPFS
	public final static String PROTO_ID = "/ipfs/id/1.0.0\n";
	public final static String PROTO_DHT = "/ipfs/kad/1.0.0\n";
	public final static String PROTO_BITSWAP = "/ipfs/bitswap/1.2.0\n";

	public String proto = null;
	public boolean handshaked = false;
	public boolean sent_handshake = false;

	/**
	 * Setup a new multistream
	 * @param	proto	Which protocol do we want. Must include \n
	 *					You can use any of the PROTO_* defs above.
	 */
	public OutgoingMultistreamSelectSession(String proto) {
		this.proto = proto;
	}

	/**
	 * Process a multistream select
	 * OUT 'multistream'
	 * OUT 'protocol'
	 * IN 'multistream'
	 * IN 'protocol'
	 *
	 * @param	in	Input buffer
	 * @param	out	An output buffer we can write to
	 *
	 * @return	true when multistream handshake has completed
	 */
	public boolean process(ByteBuffer in, ByteBuffer out) {
		if (!sent_handshake) {
			//System.out.println("MULTISTREAM SELECT " + proto);
			writeMultistream(out, MULTISTREAM);						
			writeMultistream(out, proto);
			sent_handshake = true;
		}

		if (!handshaked) {
			// We haven't performed the multistream handshake yet, so we should do that now.
			while(in.position()>0) {
				in.flip();

				// Try to read a complete packet. If we can't we abort so we can try later.
				try {
					String l = readMultistream(in);	
					logger.fine("Multistream handshake (" + l.trim() + ")");
	
					// For now, we only support multistream/1.0.0

					// TODO: FIXME
					if (l.equals(MULTISTREAM)) {
						// OK, as expected, lets reply and progress...
	
					} else if (l.equals(proto)) {
						// OK, need to move on to next stage now...
						handshaked = true;
						logger.fine("Switching to " + proto);
						in.compact();
						break;
					}
				} catch(BufferUnderflowException bue) {
					in.rewind();	// Partial packet. We'll try and read again later...
					in.compact();
					break;
				}
				in.compact();
			}
		}
		return handshaked;		
	}
	
	/**
	 * Write a multistream message
	 *
	 * @param	dest	Destination buffer
	 * @param	data	Message to write
	 */
	public static void writeMultistream(ByteBuffer dest, String data) {
		//System.out.println("MULTISTREAM DATA " + data);
		byte[] d = data.getBytes();
		writeVarInt(dest, d.length);
		dest.put(d);
	}

	/**
	 * Read a multistream message
	 *
	 * @param	src		Source buffer
	 */
	public static String readMultistream(ByteBuffer src) throws BufferUnderflowException {
		long len = readVarInt(src);
		// TODO: Sanity check, and protection here. We need to limit len.
		byte[] data = new byte[(int)len];
		src.get(data);
		return new String(data);
	}

	/**
	 * Write a variable length integer to the output buffer
	 * @param	oo	Output buffer
	 * @param	v	Value to write
	 *
	 */
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

	/**
	 * Read a variable length int from the bytebuffer
	 * @param bb	Source buffer to read from
	 *
	 */
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