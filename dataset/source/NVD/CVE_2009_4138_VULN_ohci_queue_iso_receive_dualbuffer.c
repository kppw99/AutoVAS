static int CVE_2009_4138_VULN_ohci_queue_iso_receive_dualbuffer(struct fw_iso_context *base,
					     struct fw_iso_packet *packet,
					     struct fw_iso_buffer *buffer,
					     unsigned long payload)
{
	struct iso_context *ctx = container_of(base, struct iso_context, base);
	struct db_descriptor *db = NULL;
	struct descriptor *d;
	struct fw_iso_packet *p;
	dma_addr_t d_bus, page_bus;
	u32 z, header_z, length, rest;
	int page, offset, packet_count, header_size;

	/*
	 * FIXME: Cycle lost behavior should be configurable: lose
	 * packet, retransmit or terminate..
	 */

	p = packet;
	z = 2;

	/*
	 * The OHCI controller puts the isochronous header and trailer in the
	 * buffer, so we need at least 8 bytes.
	 */
	packet_count = p->header_length / ctx->base.header_size;
	header_size = packet_count * max(ctx->base.header_size, (size_t)8);

	/* Get header size in number of descriptors. */
	header_z = DIV_ROUND_UP(header_size, sizeof(*d));
	page     = payload >> PAGE_SHIFT;
	offset   = payload & ~PAGE_MASK;
	rest     = p->payload_length;

	/* FIXME: make packet-per-buffer/dual-buffer a context option */
	while (rest > 0) {
		d = context_get_descriptors(&ctx->context,
					    z + header_z, &d_bus);
		if (d == NULL)
			return -ENOMEM;

		db = (struct db_descriptor *) d;
		db->control = cpu_to_le16(DESCRIPTOR_STATUS |
					  DESCRIPTOR_BRANCH_ALWAYS);
		db->first_size =
		    cpu_to_le16(max(ctx->base.header_size, (size_t)8));
		if (p->skip && rest == p->payload_length) {
			db->control |= cpu_to_le16(DESCRIPTOR_WAIT);
			db->first_req_count = db->first_size;
		} else {
			db->first_req_count = cpu_to_le16(header_size);
		}
		db->first_res_count = db->first_req_count;
		db->first_buffer = cpu_to_le32(d_bus + sizeof(*db));

		if (p->skip && rest == p->payload_length)
			length = 4;
		else if (offset + rest < PAGE_SIZE)
			length = rest;
		else
			length = PAGE_SIZE - offset;

		db->second_req_count = cpu_to_le16(length);
		db->second_res_count = db->second_req_count;
		page_bus = page_private(buffer->pages[page]);
		db->second_buffer = cpu_to_le32(page_bus + offset);

		if (p->interrupt && length == rest)
			db->control |= cpu_to_le16(DESCRIPTOR_IRQ_ALWAYS);

		context_append(&ctx->context, d, z, header_z);
		offset = (offset + length) & ~PAGE_MASK;
		rest -= length;
		if (offset == 0)
			page++;
	}

	return 0;
}
