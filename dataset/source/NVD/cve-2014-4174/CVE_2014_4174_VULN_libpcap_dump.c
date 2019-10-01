static gboolean CVE_2014_4174_VULN_libpcap_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const guint8 *pd, int *err)
{
	const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
	struct pcaprec_ss990915_hdr rec_hdr;
	size_t hdr_size;
	int phdrsize;

	phdrsize = pcap_get_phdr_size(wdh->encap, pseudo_header);

	rec_hdr.hdr.ts_sec = (guint32) phdr->ts.secs;
	if(wdh->tsprecision == WTAP_FILE_TSPREC_NSEC) {
		rec_hdr.hdr.ts_usec = phdr->ts.nsecs;
	} else {
		rec_hdr.hdr.ts_usec = phdr->ts.nsecs / 1000;
	}
	rec_hdr.hdr.incl_len = phdr->caplen + phdrsize;
	rec_hdr.hdr.orig_len = phdr->len + phdrsize;

	if (rec_hdr.hdr.incl_len > WTAP_MAX_PACKET_SIZE || rec_hdr.hdr.orig_len > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_FILE;
		return FALSE;
	}

	switch (wdh->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_NSEC:
		hdr_size = sizeof (struct pcaprec_hdr);
		break;

	case WTAP_FILE_PCAP_SS990417:	/* modified, but with the old magic, sigh */
	case WTAP_FILE_PCAP_SS991029:
		/* XXX - what should we supply here?

		   Alexey's "libpcap" looks up the interface in the system's
		   interface list if "ifindex" is non-zero, and prints
		   the interface name.  It ignores "protocol", and uses
		   "pkt_type" to tag the packet as "host", "broadcast",
		   "multicast", "other host", "outgoing", or "none of the
		   above", but that's it.

		   If the capture we're writing isn't a modified or
		   RH 6.1 capture, we'd have to do some work to
		   generate the packet type and interface index - and
		   we can't generate the interface index unless we
		   just did the capture ourselves in any case.

		   I'm inclined to continue to punt; systems other than
		   those with the older patch can read standard "libpcap"
		   files, and systems with the older patch, e.g. RH 6.1,
		   will just have to live with this. */
		rec_hdr.ifindex = 0;
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		hdr_size = sizeof (struct pcaprec_modified_hdr);
		break;

	case WTAP_FILE_PCAP_SS990915:	/* new magic, extra crap at the end */
		rec_hdr.ifindex = 0;
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		rec_hdr.cpu1 = 0;
		rec_hdr.cpu2 = 0;
		hdr_size = sizeof (struct pcaprec_ss990915_hdr);
		break;

	case WTAP_FILE_PCAP_NOKIA:	/* old magic, extra crap at the end */
		/* restore the "mysterious stuff" that came with the packet */
		memcpy(&rec_hdr.ifindex, pseudo_header->nokia.stuff, 4);
		/* not written */
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		rec_hdr.cpu1 = 0;
		rec_hdr.cpu2 = 0;
		hdr_size = sizeof (struct pcaprec_nokia_hdr);
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		g_assert_not_reached();
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	if (!wtap_dump_file_write(wdh, &rec_hdr, hdr_size, err))
		return FALSE;
	wdh->bytes_dumped += hdr_size;

	if (!pcap_write_phdr(wdh, wdh->encap, pseudo_header, err))
		return FALSE;

	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;
        wdh->bytes_dumped += phdr->caplen;
	return TRUE;
}
