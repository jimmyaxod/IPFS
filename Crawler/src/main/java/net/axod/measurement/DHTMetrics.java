package net.axod.measurement;

import java.util.*;
import java.util.concurrent.atomic.*;


public class DHTMetrics {
	private static HashMap total_sent_types = new HashMap();
	private static HashMap total_recv_types = new HashMap();
	
	public static void incRecvType(String type) {
		AtomicLong al = (AtomicLong)total_recv_types.get(type);
		if (al==null) {
			al = new AtomicLong(0);
			total_recv_types.put(type, al);
		}
		al.incrementAndGet();
	}

	public static void incSentType(String type) {
		AtomicLong al = (AtomicLong)total_sent_types.get(type);
		if (al==null) {
			al = new AtomicLong(0);
			total_sent_types.put(type, al);
		}
		al.incrementAndGet();
	}
	
	public static void showStatus() {
		Iterator i = total_recv_types.keySet().iterator();
		while(i.hasNext()) {
			String type = (String)i.next();
			AtomicLong al = (AtomicLong)total_recv_types.get(type);
			System.out.println("DHTMetrics recv " + type + " " + al.longValue());
		}

		Iterator j = total_sent_types.keySet().iterator();
		while(j.hasNext()) {
			String type = (String)j.next();
			AtomicLong al = (AtomicLong)total_sent_types.get(type);
			System.out.println("DHTMetrics sent " + type + " " + al.longValue());
		}
	}
}