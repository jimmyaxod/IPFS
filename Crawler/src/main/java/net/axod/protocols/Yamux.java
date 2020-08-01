package net.axod.protocols;

import java.util.*;
import java.nio.*;

/**
 * This knows about Yamux
 *
 */

public class Yamux {
	
	public static void writeYamux(ByteBuffer dest, byte[] multi_data, int m_stream, short m_flags) {
		dest.put((byte)0);		// ver
		dest.put((byte)0);		// type
		dest.putShort(m_flags);
		dest.putInt(m_stream);	// Stream ID
		dest.putInt(multi_data.length);
		dest.put(multi_data);
	}

	public static void writeYamux(ByteBuffer dest, byte[] multi_data, int m_type, int m_stream, short m_flags) {
		dest.put((byte)0);			// ver
		dest.put((byte)m_type);		// type
		dest.putShort(m_flags);
		dest.putInt(m_stream);		// Stream ID
		dest.putInt(multi_data.length);
		dest.put(multi_data);
	}

}