ieee802154_map_rec *CVE_2013_6336_VULN_ieee802154_addr_update(ieee802154_map_tab_t *au_ieee802154_map,
        guint16 short_addr, guint16 pan, guint64 long_addr, const char *proto, guint fnum)
{
    ieee802154_short_addr  addr16;
    ieee802154_map_rec    *p_map_rec;
    gpointer               old_key;

    /* Look up short address hash */
    addr16.pan = pan;
    addr16.addr = short_addr;
    p_map_rec = (ieee802154_map_rec *)g_hash_table_lookup(au_ieee802154_map->short_table, &addr16);

    /* Update mapping record */
    if (p_map_rec) {
        /* record already exists */
        if ( p_map_rec->addr64 == long_addr ) {
            /* no change */
            return p_map_rec;
        }
        else {
            /* mark current mapping record invalid */
            p_map_rec->end_fnum = fnum;
        }
    }

    /* create a new mapping record */
    p_map_rec = se_new(ieee802154_map_rec);
    p_map_rec->proto = proto;
    p_map_rec->start_fnum = fnum;
    p_map_rec->end_fnum = 0;
    p_map_rec->addr64 = long_addr;

    /* link new mapping record to addr hash tables */
    if ( g_hash_table_lookup_extended(au_ieee802154_map->short_table, &addr16, &old_key, NULL) ) {
        /* update short addr hash table, reusing pointer to old key */
        g_hash_table_insert(au_ieee802154_map->short_table, &old_key, p_map_rec);
    } else {
        /* create new hash entry */
        g_hash_table_insert(au_ieee802154_map->short_table, se_memdup(&addr16, sizeof(addr16)), p_map_rec);
    }

    if ( g_hash_table_lookup_extended(au_ieee802154_map->long_table, &long_addr, &old_key, NULL) ) {
        /* update long addr hash table, reusing pointer to old key */
        g_hash_table_insert(au_ieee802154_map->long_table, &old_key, p_map_rec);
    } else {
        /* create new hash entry */
        g_hash_table_insert(au_ieee802154_map->long_table, se_memdup(&long_addr, sizeof(long_addr)), p_map_rec);
    }

    return p_map_rec;
} /* CVE_2013_6336_VULN_ieee802154_addr_update */
