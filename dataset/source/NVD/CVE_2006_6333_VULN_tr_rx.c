static void CVE_2006_6333_VULN_tr_rx(struct net_device *dev)
{
	struct tok_info *ti = (struct tok_info *) dev->priv;
	__u32 rbuffer;
	void __iomem *rbuf, *rbufdata, *llc;
	__u8 rbuffer_page = 0;
	unsigned char *data;
	unsigned int rbuffer_len, lan_hdr_len, hdr_len, ip_len, length;
	unsigned char dlc_hdr_len;
	struct sk_buff *skb;
	unsigned int skb_size = 0;
	int IPv4_p = 0;
	unsigned int chksum = 0;
	struct iphdr *iph;
	struct arb_rec_req rarb;

	SET_PAGE(ti->arb_page);
	memcpy_fromio(&rarb, ti->arb, sizeof(rarb));
	rbuffer = ntohs(rarb.rec_buf_addr) ;
	rbuf = map_address(ti, rbuffer, &rbuffer_page);

	SET_PAGE(ti->asb_page);

	if (readb(ti->asb + RETCODE_OFST) !=0xFF) DPRINTK("ASB not free !!!\n");

	writeb(REC_DATA, ti->asb + COMMAND_OFST);
	writew(rarb.station_id, ti->asb + STATION_ID_OFST);
	writew(rarb.rec_buf_addr, ti->asb + RECEIVE_BUFFER_OFST);

	lan_hdr_len = rarb.lan_hdr_len;
	if (lan_hdr_len > sizeof(struct trh_hdr)) {
		DPRINTK("Linux cannot handle greater than 18 bytes RIF\n");
		return;
	}			/*BMS I added this above just to be very safe */
	dlc_hdr_len = readb(ti->arb + DLC_HDR_LENGTH_OFST);
	hdr_len = lan_hdr_len + sizeof(struct trllc) + sizeof(struct iphdr);

	SET_PAGE(rbuffer_page);
	llc = rbuf + offsetof(struct rec_buf, data) + lan_hdr_len;

#if TR_VERBOSE
	DPRINTK("offsetof data: %02X lan_hdr_len: %02X\n",
	(__u32) offsetof(struct rec_buf, data), (unsigned int) lan_hdr_len);
	DPRINTK("llc: %08X rec_buf_addr: %04X dev->mem_start: %lX\n",
		llc, ntohs(rarb.rec_buf_addr), dev->mem_start);
	DPRINTK("dsap: %02X, ssap: %02X, llc: %02X, protid: %02X%02X%02X, "
		"ethertype: %04X\n",
		(int) readb(llc + DSAP_OFST), (int) readb(llc + SSAP_OFST),
		(int) readb(llc + LLC_OFST), (int) readb(llc + PROTID_OFST),
		(int) readb(llc+PROTID_OFST+1),(int)readb(llc+PROTID_OFST + 2),
		(int) ntohs(readw(llc + ETHERTYPE_OFST)));
#endif
	if (readb(llc + offsetof(struct trllc, llc)) != UI_CMD) {
		SET_PAGE(ti->asb_page);
		writeb(DATA_LOST, ti->asb + RETCODE_OFST);
		ti->tr_stats.rx_dropped++;
		writeb(RESP_IN_ASB, ti->mmio + ACA_OFFSET + ACA_SET + ISRA_ODD);
		return;
	}
	length = ntohs(rarb.frame_len);
	if (readb(llc + DSAP_OFST) == EXTENDED_SAP &&
	   readb(llc + SSAP_OFST) == EXTENDED_SAP &&
		length >= hdr_len)	IPv4_p = 1;
#if TR_VERBOSE
#define SADDR_OFST	8
#define DADDR_OFST	2

	if (!IPv4_p) {

		void __iomem *trhhdr = rbuf + offsetof(struct rec_buf, data);

		DPRINTK("Probably non-IP frame received.\n");
		DPRINTK("ssap: %02X dsap: %02X "
			"saddr: %02X:%02X:%02X:%02X:%02X:%02X "
			"daddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
			readb(llc + SSAP_OFST), readb(llc + DSAP_OFST),
			readb(trhhdr+SADDR_OFST), readb(trhhdr+ SADDR_OFST+1),
			readb(trhhdr+SADDR_OFST+2), readb(trhhdr+SADDR_OFST+3),
			readb(trhhdr+SADDR_OFST+4), readb(trhhdr+SADDR_OFST+5),
			readb(trhhdr+DADDR_OFST), readb(trhhdr+DADDR_OFST + 1),
			readb(trhhdr+DADDR_OFST+2), readb(trhhdr+DADDR_OFST+3),
			readb(trhhdr+DADDR_OFST+4), readb(trhhdr+DADDR_OFST+5));
	}
#endif

	/*BMS handle the case she comes in with few hops but leaves with many */
        skb_size=length-lan_hdr_len+sizeof(struct trh_hdr)+sizeof(struct trllc);

	if (!(skb = dev_alloc_skb(skb_size))) {
		DPRINTK("out of memory. frame dropped.\n");
		ti->tr_stats.rx_dropped++;
		SET_PAGE(ti->asb_page);
		writeb(DATA_LOST, ti->asb + offsetof(struct asb_rec, ret_code));
		writeb(RESP_IN_ASB, ti->mmio + ACA_OFFSET + ACA_SET + ISRA_ODD);
		return;
	}
	/*BMS again, if she comes in with few but leaves with many */
	skb_reserve(skb, sizeof(struct trh_hdr) - lan_hdr_len);
	skb_put(skb, length);
	skb->dev = dev;
	data = skb->data;
	rbuffer_len = ntohs(readw(rbuf + offsetof(struct rec_buf, buf_len)));
	rbufdata = rbuf + offsetof(struct rec_buf, data);

	if (IPv4_p) {
		/* Copy the headers without checksumming */
		memcpy_fromio(data, rbufdata, hdr_len);

		/* Watch for padded packets and bogons */
		iph= (struct iphdr *)(data+ lan_hdr_len + sizeof(struct trllc));
		ip_len = ntohs(iph->tot_len) - sizeof(struct iphdr);
		length -= hdr_len;
		if ((ip_len <= length) && (ip_len > 7))
			length = ip_len;
		data += hdr_len;
		rbuffer_len -= hdr_len;
		rbufdata += hdr_len;
	}
	/* Copy the payload... */
#define BUFFER_POINTER_OFST	2
#define BUFFER_LENGTH_OFST      6
	for (;;) {
		if (ibmtr_debug_trace&TRC_INITV && length < rbuffer_len)
			DPRINTK("CURIOUS, length=%d < rbuffer_len=%d\n",
						length,rbuffer_len);
		if (IPv4_p)
			chksum=csum_partial_copy_nocheck((void*)rbufdata,
			    data,length<rbuffer_len?length:rbuffer_len,chksum);
		else
			memcpy_fromio(data, rbufdata, rbuffer_len);
		rbuffer = ntohs(readw(rbuf+BUFFER_POINTER_OFST)) ;
		if (!rbuffer)
			break;
		rbuffer -= 2;
		length -= rbuffer_len;
		data += rbuffer_len;
		rbuf = map_address(ti, rbuffer, &rbuffer_page);
		SET_PAGE(rbuffer_page);
		rbuffer_len = ntohs(readw(rbuf + BUFFER_LENGTH_OFST));
		rbufdata = rbuf + offsetof(struct rec_buf, data);
	}

	SET_PAGE(ti->asb_page);
	writeb(0, ti->asb + offsetof(struct asb_rec, ret_code));

	writeb(RESP_IN_ASB, ti->mmio + ACA_OFFSET + ACA_SET + ISRA_ODD);

	ti->tr_stats.rx_bytes += skb->len;
	ti->tr_stats.rx_packets++;

	skb->protocol = tr_type_trans(skb, dev);
	if (IPv4_p) {
		skb->csum = chksum;
		skb->ip_summed = 1;
	}
	netif_rx(skb);
	dev->last_rx = jiffies;
}				/*CVE_2006_6333_VULN_tr_rx */
