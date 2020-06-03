static void
CVE_2013_4921_VULN_dissect_radiotap(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	proto_tree *radiotap_tree     = NULL;
	proto_tree *pt, *present_tree = NULL;
	proto_tree *ft;
	proto_item *ti                = NULL;
	proto_item *hidden_item;
	int         offset;
	tvbuff_t   *next_tvb;
	guint8      version;
	guint       length;
	guint32     freq;
	proto_item *rate_ti;
	gint8       dbm, db;
	guint8      rflags            = 0;
	/* backward compat with bit 14 == fcs in header */
	proto_item *hdr_fcs_ti        = NULL;
	int         hdr_fcs_offset    = 0;
	guint32     sent_fcs          = 0;
	guint32     calc_fcs;
	gint        err               = -ENOENT;
	void       *data;
	struct _radiotap_info              *radiotap_info;
	static struct _radiotap_info        rtp_info_arr;
	struct ieee80211_radiotap_iterator  iter;

	/* our non-standard overrides */
	static struct radiotap_override overrides[] = {
		{IEEE80211_RADIOTAP_XCHANNEL, 4, 8},	/* xchannel */

		/* keep last */
		{14, 4, 4},	/* FCS in header */
	};
	guint n_overrides = array_length(overrides);

	if (!radiotap_bit14_fcs)
		n_overrides--;

	radiotap_info = &rtp_info_arr;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLAN");
	col_clear(pinfo->cinfo, COL_INFO);

	version = tvb_get_guint8(tvb, 0);
	length = tvb_get_letohs(tvb, 2);

	radiotap_info->radiotap_length = length;

	col_add_fstr(pinfo->cinfo, COL_INFO, "Radiotap Capture v%u, Length %u",
		     version, length);

	/* Dissect the packet */
	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_radiotap,
						    tvb, 0, length,
						    "Radiotap Header v%u, Length %u",
						    version, length);
		radiotap_tree = proto_item_add_subtree(ti, ett_radiotap);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_version,
				    tvb, 0, 1, version);
		proto_tree_add_item(radiotap_tree, hf_radiotap_pad,
				    tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_length,
				    tvb, 2, 2, length);
	}

	data = ep_tvb_memdup(tvb, 0, length);
	if (!data)
		return;

	if (ieee80211_radiotap_iterator_init(&iter, (struct ieee80211_radiotap_header *)data, length, NULL)) {
		if (tree)
			proto_item_append_text(ti, " (invalid)");
		/* maybe the length was correct anyway ... */
		goto hand_off_to_80211;
	}

	iter.overrides = overrides;
	iter.n_overrides = n_overrides;

	/* Add the "present flags" bitmaps. */
	if (tree) {
		guchar	 *bmap_start	      = (guchar *)data + 4;
		guint	  n_bitmaps	      = (guint)(iter.this_arg - bmap_start) / 4;
		guint	  i;
		gboolean  rtap_ns;
		gboolean  rtap_ns_next	      = TRUE;
		guint	  rtap_ns_offset;
		guint	  rtap_ns_offset_next = 0;

		pt = proto_tree_add_item(radiotap_tree, hf_radiotap_present,
					 tvb, 4, n_bitmaps * 4,
					 ENC_NA);

		for (i = 0; i < n_bitmaps; i++) {
			guint32 bmap = pletohl(bmap_start + 4 * i);

			rtap_ns_offset = rtap_ns_offset_next;
			rtap_ns_offset_next += 32;

			present_tree =
			    proto_item_add_subtree(pt, ett_radiotap_present);

			offset = 4 * i;

			rtap_ns = rtap_ns_next;

			/* Evaluate what kind of namespaces will come next */
			if (bmap & BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE)) {
				rtap_ns_next = TRUE;
				rtap_ns_offset_next = 0;
			}
			if (bmap & BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE))
				rtap_ns_next = FALSE;
			if ((bmap & (BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE) |
				     BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE)))
				== (BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE) |
				    BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE)))
				goto malformed;

			if (!rtap_ns)
				goto always_bits;

			/* Currently, we don't know anything about bits >= 32 */
			if (rtap_ns_offset)
				goto always_bits;

			proto_tree_add_item(present_tree,
					    hf_radiotap_present_tsft, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_flags, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_rate, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_channel, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_fhss, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_dbm_antsignal,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_dbm_antnoise,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_lock_quality,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_tx_attenuation,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_db_tx_attenuation,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_dbm_tx_power,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_antenna, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_db_antsignal,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_db_antnoise,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			if (radiotap_bit14_fcs) {
				proto_tree_add_item(present_tree,
						    hf_radiotap_present_hdrfcs,
						    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			} else {
				proto_tree_add_item(present_tree,
						    hf_radiotap_present_rxflags,
						    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			}
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_xchannel, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);

			proto_tree_add_item(present_tree,
					    hf_radiotap_present_mcs, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_ampdu, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_vht, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			ti = proto_tree_add_item(present_tree,
					    hf_radiotap_present_reserved, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			/* Check if Reserved/Not Defined is not "zero" */
			if(bmap & IEEE80211_RADIOTAP_NOTDEFINED)
			{
				expert_add_info_format(pinfo,ti, PI_UNDECODED, PI_NOTE,
				"Unknown Radiotap fields, code not implemented, "
				"Please check radiotap documentation, "
				"Contact Wireshark developers if you want this supported" );
			}
 always_bits:
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_rtap_ns, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_vendor_ns, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_ext, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
		}
	}

	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		offset = (int)((guchar *) iter.this_arg - (guchar *) data);

		if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE
		    && tree) {
			proto_tree *vt, *ven_tree = NULL;
			const gchar *manuf_name;
			guint8 subns;

			manuf_name = tvb_get_manuf_name(tvb, offset);
			subns = tvb_get_guint8(tvb, offset+3);

			vt = proto_tree_add_bytes_format(radiotap_tree,
							 hf_radiotap_vendor_ns,
							 tvb, offset,
							 iter.this_arg_size,
							 NULL,
							 "Vendor namespace: %s-%d",
							 manuf_name, subns);
			ven_tree = proto_item_add_subtree(vt, ett_radiotap_vendor);
			proto_tree_add_bytes_format(ven_tree,
						    hf_radiotap_ven_oui, tvb,
						    offset, 3, NULL,
						    "Vendor: %s", manuf_name);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_subns,
					    tvb, offset + 3, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_skip, tvb,
					    offset + 4, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_data, tvb,
					    offset + 6, iter.this_arg_size - 6,
					    ENC_NA);
		}

		if (!iter.is_radiotap_ns)
			continue;

		switch (iter.this_arg_index) {

		case IEEE80211_RADIOTAP_TSFT:
			radiotap_info->tsft = tvb_get_letoh64(tvb, offset);
			if (tree) {
				proto_tree_add_uint64(radiotap_tree,
						      hf_radiotap_mactime, tvb,
						      offset, 8,
						      radiotap_info->tsft);
			}
			break;

		case IEEE80211_RADIOTAP_FLAGS: {
			rflags = tvb_get_guint8(tvb, offset);
			if (tree) {
				proto_tree *flags_tree;

				ft = proto_tree_add_item(radiotap_tree,
							 hf_radiotap_flags,
							 tvb, offset, 1, ENC_BIG_ENDIAN);
				flags_tree =
				    proto_item_add_subtree(ft,
							   ett_radiotap_flags);

				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_cfp,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_preamble,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_wep,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_frag,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_fcs,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_datapad,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_badfcs,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_shortgi,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
			}
			break;
		}

		case IEEE80211_RADIOTAP_RATE: {
			guint32 rate;
			rate = tvb_get_guint8(tvb, offset);
			/*
			 * XXX On FreeBSD rate & 0x80 means we have an MCS. On
			 * Linux and AirPcap it does not.  (What about
			 * Mac OS X, NetBSD, OpenBSD, and DragonFly BSD?)
			 *
			 * This is an issue either for proprietary extensions
			 * to 11a or 11g, which do exist, or for 11n
			 * implementations that stuff a rate value into
			 * this field, which also appear to exist.
			 *
			 * We currently handle that by assuming that
			 * if the 0x80 bit is set *and* the remaining
			 * bits have a value between 0 and 15 it's
			 * an MCS value, otherwise it's a rate.  If
			 * there are cases where systems that use
			 * "0x80 + MCS index" for MCS indices > 15,
			 * or stuff a rate value here between 64 and
			 * 71.5 Mb/s in here, we'll need a preference
			 * setting.  Such rates do exist, e.g. 11n
			 * MCS 7 at 20 MHz with a long guard interval.
			 */
			if (rate >= 0x80 && rate <= 0x8f) {
				/*
				 * XXX - we don't know the channel width
				 * or guard interval length, so we can't
				 * convert this to a data rate.
				 *
				 * If you want us to show a data rate,
				 * use the MCS field, not the Rate field;
				 * the MCS field includes not only the
				 * MCS index, it also includes bandwidth
				 * and guard interval information.
				 *
				 * XXX - can we get the channel width
				 * from XChannel and the guard interval
				 * information from Flags, at least on
				 * FreeBSD?
				 */
				if (tree) {
					proto_tree_add_uint(radiotap_tree,
							    hf_radiotap_mcs_index,
							    tvb, offset, 1,
							    rate & 0x7f);
				}
			} else {
				col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%d.%d",
					     rate / 2, rate & 1 ? 5 : 0);
				if (tree) {
					proto_tree_add_float_format(radiotap_tree,
								    hf_radiotap_datarate,
								    tvb, offset, 1,
								    (float)rate / 2,
								    "Data Rate: %.1f Mb/s",
								    (float)rate / 2);
				}
				radiotap_info->rate = rate;
			}
			break;
		}

		case IEEE80211_RADIOTAP_CHANNEL: {
			if (tree) {
				proto_item *it;
				proto_tree *flags_tree;
				guint16     flags;
				gchar	   *chan_str;

				freq	 = tvb_get_letohs(tvb, offset);
				flags	 = tvb_get_letohs(tvb, offset + 2);
				chan_str = ieee80211_mhz_to_str(freq);
				col_add_fstr(pinfo->cinfo,
					     COL_FREQ_CHAN, "%s", chan_str);
				proto_tree_add_uint_format(radiotap_tree,
							   hf_radiotap_channel_frequency,
							   tvb, offset, 2, freq,
							   "Channel frequency: %s",
							   chan_str);
				g_free(chan_str);
				/* We're already 2-byte aligned. */
				it = proto_tree_add_uint(radiotap_tree,
							 hf_radiotap_channel_flags,
							 tvb, offset + 2, 2, flags);
				flags_tree =
				    proto_item_add_subtree(it,
							   ett_radiotap_channel_flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_turbo,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_cck,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_ofdm,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_2ghz,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_5ghz,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_passive,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_dynamic,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_gfsk,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_gsm,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_sturbo,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_half,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_quarter,
						       tvb, offset + 3, 1, flags);
				radiotap_info->freq = freq;
				radiotap_info->flags = flags;
			}
			break;
		}

		case IEEE80211_RADIOTAP_FHSS:
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_fhss_hopset, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_fhss_pattern, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			break;

		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			dbm = (gint8)tvb_get_guint8(tvb, offset);
			col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);
			if (tree) {
				proto_tree_add_int_format(radiotap_tree,
							  hf_radiotap_dbm_antsignal,
							  tvb, offset, 1, dbm,
							  "SSI Signal: %d dBm",
							  dbm);
			}
			radiotap_info->dbm_antsignal = dbm;
			break;

		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
			dbm = (gint8) tvb_get_guint8(tvb, offset);
			if (tree) {
				proto_tree_add_int_format(radiotap_tree,
							  hf_radiotap_dbm_antnoise,
							  tvb, offset, 1, dbm,
							  "SSI Noise: %d dBm",
							  dbm);
			}
			radiotap_info->dbm_antnoise = dbm;
			break;

		case IEEE80211_RADIOTAP_LOCK_QUALITY:
			if (tree) {
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_quality, tvb,
						    offset, 2,
						    tvb_get_letohs(tvb,
								   offset));
			}
			break;

		case IEEE80211_RADIOTAP_TX_ATTENUATION:
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_tx_attenuation, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
			break;

		case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_db_tx_attenuation, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
			break;

		case IEEE80211_RADIOTAP_DBM_TX_POWER:
			if (tree) {
				proto_tree_add_int(radiotap_tree,
						   hf_radiotap_txpower, tvb,
						   offset, 1,
						   tvb_get_guint8(tvb, offset));
			}
			break;

		case IEEE80211_RADIOTAP_ANTENNA:
			if (tree) {
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_antenna, tvb,
						    offset, 1,
						    tvb_get_guint8(tvb,
								   offset));
			}
			break;

		case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
			db = tvb_get_guint8(tvb, offset);
			col_add_fstr(pinfo->cinfo, COL_RSSI, "%u dB", db);
			if (tree) {
				proto_tree_add_uint_format(radiotap_tree,
							   hf_radiotap_db_antsignal,
							   tvb, offset, 1, db,
							   "SSI Signal: %u dB",
							   db);
			}
			break;

		case IEEE80211_RADIOTAP_DB_ANTNOISE:
			db = tvb_get_guint8(tvb, offset);
			if (tree) {
				proto_tree_add_uint_format(radiotap_tree,
							   hf_radiotap_db_antnoise,
							   tvb, offset, 1, db,
							   "SSI Noise: %u dB",
							   db);
			}
			break;

		case IEEE80211_RADIOTAP_RX_FLAGS: {
			if (radiotap_bit14_fcs) {
				if (tree) {
					sent_fcs   = tvb_get_ntohl(tvb, offset);
					hdr_fcs_ti = proto_tree_add_uint(radiotap_tree,
									 hf_radiotap_fcs, tvb,
									 offset, 4, sent_fcs);
					hdr_fcs_offset = offset;
				}
			} else {

				if (tree) {
					proto_tree *flags_tree;
					proto_item *it;
					guint16	    flags;
					flags = tvb_get_letohs(tvb, offset);
					it = proto_tree_add_uint(radiotap_tree,
								 hf_radiotap_rxflags,
								 tvb, offset, 2, flags);
					flags_tree =
					    proto_item_add_subtree(it,
								   ett_radiotap_rxflags);
					proto_tree_add_boolean(flags_tree,
							       hf_radiotap_rxflags_badplcp,
							       tvb, offset, 1, flags);
				}
			}
			break;
		}

		case IEEE80211_RADIOTAP_XCHANNEL: {
			if (tree) {
				proto_item *it;
				proto_tree *flags_tree;
				guint32     flags;
				int	    channel;

				flags   = tvb_get_letohl(tvb, offset);
				freq    = tvb_get_letohs(tvb, offset + 4);
				channel = tvb_get_guint8(tvb, offset + 6);
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_xchannel,
						    tvb, offset + 6, 1,
						    (guint32) channel);
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_xchannel_frequency,
						    tvb, offset + 4, 2, freq);
				it = proto_tree_add_uint(radiotap_tree,
							 hf_radiotap_xchannel_flags,
							 tvb, offset + 0, 4, flags);
				flags_tree =
				    proto_item_add_subtree(it, ett_radiotap_xchannel_flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_turbo,
						       tvb, offset + 0, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_cck,
						       tvb, offset + 0, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_ofdm,
						       tvb, offset + 0, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_2ghz,
						       tvb, offset + 0, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_5ghz,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_passive,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_dynamic,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_gfsk,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_gsm,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_sturbo,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_half,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_quarter,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_ht20,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_ht40u,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_ht40d,
						       tvb, offset + 2, 1, flags);
#if 0
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_xchannel_maxpower,
						    tvb, offset + 7, 1, maxpower);
#endif
			}
			break;
		}
		case IEEE80211_RADIOTAP_MCS: {
			proto_tree *mcs_tree = NULL, *mcs_known_tree;
			guint8	    mcs_known, mcs_flags;
			guint8	    mcs;
			guint	    bandwidth;
			guint	    gi_length;
			gboolean    can_calculate_rate;

			/*
			 * Start out assuming that we can calculate the rate;
			 * if we are missing any of the MCS index, channel
			 * width, or guard interval length, we can't.
			 */
			can_calculate_rate = TRUE;

			mcs_known = tvb_get_guint8(tvb, offset);
			mcs_flags = tvb_get_guint8(tvb, offset + 1);
			mcs = tvb_get_guint8(tvb, offset + 2);

			if (tree) {
				proto_item *it;

				it = proto_tree_add_item(radiotap_tree, hf_radiotap_mcs,
							 tvb, offset, 3, ENC_NA);
				mcs_tree = proto_item_add_subtree(it, ett_radiotap_mcs);
				it = proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_known,
							 tvb, offset, 1, mcs_known);
				mcs_known_tree = proto_item_add_subtree(it, ett_radiotap_mcs_known);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_bw,
					    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_index,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_gi,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_format,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_fec,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_stbc,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
				bandwidth = ((mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_40) ?
				    1 : 0;
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_bw,
							    tvb, offset + 1, 1, mcs_flags);
			} else {
				bandwidth = 0;
				can_calculate_rate = FALSE;	/* no bandwidth */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
				gi_length = (mcs_flags & IEEE80211_RADIOTAP_MCS_SGI) ?
				    1 : 0;
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_gi,
							    tvb, offset + 1, 1, mcs_flags);
			} else {
				gi_length = 0;
				can_calculate_rate = FALSE;	/* no GI width */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FMT) {
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_format,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FEC) {
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_fec,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_STBC) {
				if (mcs_tree)
					proto_tree_add_boolean(mcs_tree, hf_radiotap_mcs_stbc,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_index,
							    tvb, offset + 2, 1, mcs);
			} else
				can_calculate_rate = FALSE;	/* no MCS index */

			/*
			 * If we have the MCS index, channel width, and
			 * guard interval length, and the MCS index is
			 * valid, we can compute the rate.  If the resulting
			 * rate is non-zero, report it.  (If it's zero,
			 * it's an MCS/channel width/GI combination that
			 * 802.11n doesn't support.)
			 */
			if (can_calculate_rate && mcs <= MAX_MCS_INDEX
			    && ieee80211_float_htrates[mcs][bandwidth][gi_length] != 0.0) {
				col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f",
					     ieee80211_float_htrates[mcs][bandwidth][gi_length]);
				if (tree) {
					rate_ti = proto_tree_add_float_format(radiotap_tree,
					    hf_radiotap_datarate,
					    tvb, offset, 3,
					    ieee80211_float_htrates[mcs][bandwidth][gi_length],
					    "Data Rate: %.1f Mb/s",
					    ieee80211_float_htrates[mcs][bandwidth][gi_length]);
					PROTO_ITEM_SET_GENERATED(rate_ti);
				}
			}
			break;
		}
		case IEEE80211_RADIOTAP_AMPDU_STATUS: {
			proto_item *it;
			proto_tree *ampdu_tree = NULL, *ampdu_flags_tree;
			guint16	    flags;

			flags = tvb_get_letohs(tvb, offset + 4);

			if (tree) {
				it = proto_tree_add_item(radiotap_tree, hf_radiotap_ampdu,
							 tvb, offset, 8, ENC_NA);
				ampdu_tree = proto_item_add_subtree(it, ett_radiotap_ampdu);

				proto_tree_add_item(ampdu_tree, hf_radiotap_ampdu_ref,
						    tvb, offset, 4, ENC_LITTLE_ENDIAN);

				it = proto_tree_add_item(ampdu_tree, hf_radiotap_ampdu_flags,
							 tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				ampdu_flags_tree = proto_item_add_subtree(it, ett_radiotap_ampdu_flags);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_report_zerolen,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_is_zerolen,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_last_known,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_is_last,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_delim_crc_error,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
			}
			if (flags & IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_KNOWN) {
				if (ampdu_tree)
					proto_tree_add_item(ampdu_tree, hf_radiotap_ampdu_delim_crc,
							    tvb, offset + 6, 1, ENC_NA);
			}
			break;
		}
		case IEEE80211_RADIOTAP_VHT: {
			proto_item *it, *it_root = NULL;
			proto_tree *vht_tree	 = NULL, *vht_known_tree = NULL, *user_tree = NULL;
			guint16	    known, nsts;
			guint8	    flags, bw, mcs_nss;
			guint	    bandwidth	 = 0;
			guint	    gi_length	 = 0;
			guint	    nss		 = 0;
			guint	    mcs		 = 0;
			gboolean    can_calculate_rate;
			guint	    i;

			/*
			 * Start out assuming that we can calculate the rate;
			 * if we are missing any of the MCS index, channel
			 * width, or guard interval length, we can't.
			 */
			can_calculate_rate = TRUE;

			known = tvb_get_letohs(tvb, offset);
			flags = tvb_get_guint8(tvb, offset + 2);
			bw    = tvb_get_guint8(tvb, offset + 3);

			if (tree) {
				it_root = proto_tree_add_item(radiotap_tree, hf_radiotap_vht,
						tvb, offset, 12, ENC_NA);
				vht_tree = proto_item_add_subtree(it_root, ett_radiotap_vht);
				it = proto_tree_add_item(vht_tree, hf_radiotap_vht_known,
						tvb, offset, 2, known);
				vht_known_tree = proto_item_add_subtree(it, ett_radiotap_vht_known);

				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_stbc,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_txop_ps,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_gi,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_sgi_nsym_da,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_ldpc_extra,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_bf,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_bw,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_gid,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_p_aid,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_STBC) {
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_stbc,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_TXOP_PS) {
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_txop_ps,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_GI) {
				gi_length = (flags & IEEE80211_RADIOTAP_VHT_SGI) ? 1 : 0;
				if (vht_tree) {
					proto_tree_add_item(vht_tree, hf_radiotap_vht_gi,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(vht_tree, hf_radiotap_vht_sgi_nsym_da,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
				}
			} else {
				can_calculate_rate = FALSE;	/* no GI width */
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_LDPC_EXTRA) {
				if (vht_tree) {
					proto_tree_add_item(vht_tree, hf_radiotap_vht_ldpc_extra,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
				}
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_BF) {
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_bf,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_BW) {
				if (bw <= sizeof(ieee80211_vht_bw2rate_index)/sizeof(ieee80211_vht_bw2rate_index[0]))
					bandwidth = ieee80211_vht_bw2rate_index[bw];
				else
					can_calculate_rate = FALSE; /* unknown bandwidth */

				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_bw,
							tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
			} else {
				can_calculate_rate = FALSE;	/* no bandwidth */
			}

			for(i=0; i<4; i++) {
				mcs_nss = tvb_get_guint8(tvb, offset + 4 + i);
				nss = (mcs_nss & IEEE80211_RADIOTAP_VHT_NSS);
				mcs = (mcs_nss & IEEE80211_RADIOTAP_VHT_MCS) >> 4;

				if ((known & IEEE80211_RADIOTAP_VHT_HAVE_STBC) && (flags & IEEE80211_RADIOTAP_VHT_STBC))
					nsts = 2 * nss;
				else
					nsts = nss;

				if (nss) {
					if (vht_tree) {
						it = proto_tree_add_item(vht_tree, hf_radiotap_vht_user,
							tvb, offset + 4, 5, ENC_NA);
						proto_item_append_text(it, " %d: MCS %u", i, mcs);
						user_tree = proto_item_add_subtree(it, ett_radiotap_vht_user);

						it = proto_tree_add_item(user_tree, hf_radiotap_vht_mcs[i],
							tvb, offset + 4 + i, 1,
							ENC_LITTLE_ENDIAN);
						if (mcs > MAX_MCS_VHT_INDEX) {
							proto_item_append_text(it, " (invalid)");
						} else {
							proto_item_append_text(it, " (%s %s)",
								ieee80211_vhtinfo[mcs].modulation,
								ieee80211_vhtinfo[mcs].coding_rate);
						}

						proto_tree_add_item(user_tree, hf_radiotap_vht_nss[i],
							tvb, offset + 4 + i, 1, ENC_LITTLE_ENDIAN);
						proto_tree_add_uint(user_tree, hf_radiotap_vht_nsts[i],
							tvb, offset + 4 + i, 1, nsts);
						proto_tree_add_item(user_tree, hf_radiotap_vht_coding[i],
							tvb, offset + 8, 1,ENC_LITTLE_ENDIAN);
					}

					if (can_calculate_rate) {
						float rate = ieee80211_vhtinfo[mcs].rates[bandwidth][gi_length] * nss;
						if (rate != 0.0f && user_tree) {
							rate_ti = proto_tree_add_float_format(user_tree,
									hf_radiotap_vht_datarate[i],
									tvb, offset, 12, rate,
									"Data Rate: %.1f Mb/s", rate);
							PROTO_ITEM_SET_GENERATED(rate_ti);
						}
					}
				}
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_GID) {
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_gid,
							tvb, offset+9, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_PAID) {
				if (vht_tree) {
					proto_tree_add_item(vht_tree, hf_radiotap_vht_p_aid,
							tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
				}
			}

			break;
		}
		}
	}

	if (err != -ENOENT && tree) {
 malformed:
		proto_item_append_text(ti, " (malformed)");
	}

	/* This handles the case of an FCS exiting at the end of the frame. */
	if (rflags & IEEE80211_RADIOTAP_F_FCS)
		pinfo->pseudo_header->ieee_802_11.fcs_len = 4;
	else
		pinfo->pseudo_header->ieee_802_11.fcs_len = 0;

 hand_off_to_80211:
	/* Grab the rest of the frame. */
	next_tvb = tvb_new_subset_remaining(tvb, length);

	/* If we had an in-header FCS, check it.
	 * This can only happen if the backward-compat configuration option
	 * is chosen by the user. */
	if (hdr_fcs_ti) {
		/* It would be very strange for the header to have an FCS for the
		 * frame *and* the frame to have the FCS at the end, but it's possible, so
		 * take that into account by using the FCS length recorded in pinfo. */

		/* Watch out for [erroneously] short frames */
		if (tvb_length(next_tvb) >
		    (unsigned int)pinfo->pseudo_header->ieee_802_11.fcs_len) {
			calc_fcs =
			    crc32_802_tvb(next_tvb,
			    	tvb_length(next_tvb) -
			    	pinfo->pseudo_header->ieee_802_11.fcs_len);

			/* By virtue of hdr_fcs_ti being set, we know that 'tree' is set,
			 * so there's no need to check it here. */
			if (calc_fcs == sent_fcs) {
				proto_item_append_text(hdr_fcs_ti,
						       " [correct]");
			} else {
				proto_item_append_text(hdr_fcs_ti,
						       " [incorrect, should be 0x%08x]",
						       calc_fcs);
				hidden_item =
				    proto_tree_add_boolean(radiotap_tree,
							   hf_radiotap_fcs_bad,
							   tvb, hdr_fcs_offset,
							   4, TRUE);
				PROTO_ITEM_SET_HIDDEN(hidden_item);
			}
		} else {
			proto_item_append_text(hdr_fcs_ti,
					       " [cannot verify - not enough data]");
		}
	}

	/* dissect the 802.11 header next */
	call_dissector((rflags & IEEE80211_RADIOTAP_F_DATAPAD) ?
		       ieee80211_datapad_handle : ieee80211_handle,
		       next_tvb, pinfo, tree);

	tap_queue_packet(radiotap_tap, pinfo, radiotap_info);
}
