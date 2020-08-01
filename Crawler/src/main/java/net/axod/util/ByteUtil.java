package net.axod.util;


public class ByteUtil {
    private static void showHexData(byte[] d) {
		int o = 0;
		while(true) {
			String l = "";
			for(int i=0;i<Math.min(16, d.length - o); i++) {
				String ch = "00" + Integer.toString(((int)d[o+i]) & 0xff, 16);
				ch = ch.substring(ch.length() - 2, ch.length());
				l += " " + ch;
			}
			System.out.println(" " + l);
			o+=16;
			if (o>=d.length) break;
		}
	}

	public static String toHexString(byte[] d) {
		String o = "";
		for(int i=0;i<d.length;i++) {
			String ch = "00" + Integer.toString(((int)d[i]) & 0xff, 16);
			ch = ch.substring(ch.length() - 2, ch.length());
			o=o+ch;
		}
		return o;
	}
	
	public static byte[] fromHexString(String d) {
		byte[] o = new byte[d.length() / 2];
		for(int i=0;i<o.length;i++) {
			o[i] = (byte)Integer.parseInt(d.substring(i*2, i*2 + 2), 16);
		}
		return o;
	}
}