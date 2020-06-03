static void
CVE_2013_1572_VULN_dissect_oampdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8    oampdu_code;
    guint16   flags,state;
    guint32   i;

    proto_tree *oampdu_tree;
    proto_item *oampdu_item;
    proto_tree *flags_tree;
    proto_item *flags_item;

    const char *sep = initial_sep;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OAM");

    oampdu_code = tvb_get_guint8(tvb, OAMPDU_CODE);

    switch (oampdu_code)
    {
        case OAMPDU_INFORMATION:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Information");
            break;
        case OAMPDU_EVENT_NOTIFICATION:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Event Notification");
            break;
        case OAMPDU_VAR_REQUEST:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Variable Request");
            break;
        case OAMPDU_VAR_RESPONSE:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Variable Response");
            break;
        case OAMPDU_LOOPBACK_CTRL:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Loopback Control");
            break;
        case OAMPDU_VENDOR_SPECIFIC:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Organization Specific");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU reserved");
            break;
    }


    if (tree)
    {
        /* Add OAM Heading */
        oampdu_item = proto_tree_add_protocol_format(tree, proto_slow, tvb,
                0, -1, "OAM Protocol");
        oampdu_tree = proto_item_add_subtree(oampdu_item, ett_oampdu);

        /* Subtype */
        proto_tree_add_item(oampdu_tree, hf_slow_subtype, tvb,
                0, 1, ENC_BIG_ENDIAN);

        /* Flags field */
        flags = tvb_get_ntohs(tvb, OAMPDU_FLAGS);
        flags_item = proto_tree_add_uint(oampdu_tree, hf_oampdu_flags, tvb,
                OAMPDU_FLAGS, 2, flags);
        flags_tree = proto_item_add_subtree(flags_item, ett_oampdu_flags);

        /*
         * In this section we add keywords for the bit set on the Flags's line.
         * We also add all the bit inside the subtree.
         */
        APPEND_BOOLEAN_FLAG(flags & OAMPDU_FLAGS_LINK_FAULT, flags_item,
                "%sLink Fault");
        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_link_fault,
                tvb, OAMPDU_FLAGS, 1, flags);

        APPEND_BOOLEAN_FLAG(flags & OAMPDU_FLAGS_DYING_GASP, flags_item,
                "%sDying Gasp");
        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_dying_gasp,
                tvb, OAMPDU_FLAGS, 1, flags);

        APPEND_BOOLEAN_FLAG(flags & OAMPDU_FLAGS_CRITICAL_EVENT, flags_item,
                "%sCriticalEvent");
        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_critical_event,
                tvb, OAMPDU_FLAGS, 1, flags);

        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_local_evaluating,
                tvb, OAMPDU_FLAGS, 1, flags);

        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_local_stable,
                tvb, OAMPDU_FLAGS, 1, flags);

        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_remote_evaluating,
                tvb, OAMPDU_FLAGS, 1, flags);

        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_remote_stable,
                tvb, OAMPDU_FLAGS, 1, flags);

        if (sep != cont_sep)
            proto_item_append_text(flags_item, " (");
        else
            proto_item_append_text(flags_item, ", ");

        for(i=0;i<2;i++)
        {
            if (i==0)
            {
                proto_item_append_text(flags_item, "local: ");
                state = (flags&(OAMPDU_FLAGS_LOCAL_EVAL|OAMPDU_FLAGS_LOCAL_STABLE));
                state = state>>3;
            }
            else
            {
                proto_item_append_text(flags_item, "remote: ");
                state = (flags&(OAMPDU_FLAGS_REMOTE_EVAL|OAMPDU_FLAGS_REMOTE_STABLE));
                state = state>>5;
            }

            switch (state)
            {
                case 0:
                    proto_item_append_text(flags_item, "Unsatisfied");
                    break;
                case 1:
                    proto_item_append_text(flags_item, "Discovery in process");
                    break;
                case 2:
                    proto_item_append_text(flags_item, "Discovery complete");
                    break;
                default:
                    proto_item_append_text(flags_item, "Reserved");
                    break;
            }

            if (i==0)
                proto_item_append_text(flags_item, ", ");

        }

        proto_item_append_text(flags_item, ")");

        /* OAMPDU code */
        oampdu_code = tvb_get_guint8(tvb, OAMPDU_CODE);
        proto_tree_add_uint(oampdu_tree, hf_oampdu_code, tvb,
                OAMPDU_CODE, 1, oampdu_code);

        switch (oampdu_code)
        {
            case OAMPDU_INFORMATION:
                dissect_oampdu_information(tvb, oampdu_tree);
                break;
            case OAMPDU_EVENT_NOTIFICATION:
                dissect_oampdu_event_notification(tvb, oampdu_tree);
                break;
            case OAMPDU_VAR_REQUEST:
                dissect_oampdu_variable_request(tvb, oampdu_tree);
                break;
            case OAMPDU_VAR_RESPONSE:
                dissect_oampdu_variable_response(tvb, oampdu_tree);
                break;
            case OAMPDU_LOOPBACK_CTRL:
                dissect_oampdu_loopback_control(tvb, oampdu_tree);
                break;
            case OAMPDU_VENDOR_SPECIFIC:
                dissect_oampdu_vendor_specific(tvb, oampdu_tree);
            default:
                break;
        }
    }
}
