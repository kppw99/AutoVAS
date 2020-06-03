guint16 CVE_2013_4932_PATCHED_elem_v_short(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint pdu_type, int idx, guint32 offset, guint32 nibble)
{
    guint16             consumed = 1;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    value_string_ext    elem_names_ext;
    gint               *elem_ett;
    elem_fcn           *elem_funcs;
    gchar              *a_add_string;
    const gchar        *elem_name;

    curr_offset = offset;

    SET_ELEM_VARS(pdu_type, elem_names_ext, elem_ett, elem_funcs);

    elem_name = try_val_to_str_ext(idx, &elem_names_ext);

    item = proto_tree_add_text(tree,
            tvb, curr_offset, 0,
            "%s%s", elem_name ? elem_name : "Unknown - aborting dissection",
            "");

    /* idx is out of range */
    if (elem_name == NULL)
        return(consumed);

    subtree = proto_item_add_subtree(item, elem_ett[idx]);

    a_add_string= (gchar*)ep_alloc(1024);
    a_add_string[0] = '\0';

    if (elem_funcs[idx] == NULL)
    {
        /* NOT NECESSARILY A BAD THING - LENGTH IS HALF OCTET */
        (void)de_spare_nibble(tvb, subtree, pinfo, curr_offset, nibble, a_add_string, 1024);
    }
    else
    {
        (void)(*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset, nibble, a_add_string, 1024);
    }

    if (a_add_string[0] != '\0')
    {
        proto_item_append_text(item, "%s", a_add_string);
    }
    proto_item_set_len(item, consumed);

    return(consumed);
}
