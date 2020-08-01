package net.axod.protocols;

import java.nio.*;

/**
 * This knows about multistream
 * It can read and write
 *
 */
 
public class Multistream {
	public final static String MULTISTREAM = "/multistream/1.0.0\n";
	
	public final static String PROTO_SECIO = "/secio/1.0.0\n";
	public final static String PROTO_YAMUX = "/yamux/1.0.0\n";
	
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