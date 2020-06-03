static int CVE_2013_2486_VULN_dissect_diagnosticrequest(int anchor, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length) {
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16     local_offset = 0;
  guint32     local_length = 0;
  int         hf           = hf_reload_diagnosticrequest;

  if (anchor >= 0) {
    hf = anchor;
  }

  ti_local = proto_tree_add_item(tree, hf, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_diagnosticrequest);

  proto_tree_add_item(local_tree, hf_reload_diagnostic_expiration, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
  local_offset += 8;
  proto_tree_add_item(local_tree, hf_reload_diagnosticrequest_timestampinitiated, tvb,
                      offset+local_offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
  local_offset += 8;
  local_length = tvb_get_ntohl(tvb, offset+local_offset);
  proto_tree_add_item(local_tree, hf_reload_length_uint32, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
  local_offset += 4;

  local_offset += dissect_dmflag(tvb, local_tree, offset+local_offset);
  if (local_offset+local_length > length) {
    expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated DiagnosticRequest");
    local_length = length-local_offset;
  }
  if (local_length>0) {
    proto_item *ti_extensions;
    proto_tree *extensions_tree;
    guint16     extensions_offset = 0;
    guint32     extensions_length = 0;
    int         nExtensions       = 0;

    ti_extensions = proto_tree_add_item(local_tree, hf_reload_diagnosticrequest_extensions, tvb, offset+local_offset, local_length, ENC_NA);
    extensions_tree = proto_item_add_subtree(ti_extensions, ett_reload_diagnosticrequest_extensions);
    extensions_length = tvb_get_ntohl(tvb, offset+local_offset);
    if (extensions_length+4 > local_length) {
      expert_add_info_format(pinfo, ti_extensions, PI_PROTOCOL, PI_ERROR, "Truncated Diagnostic extensions");
      extensions_length = local_length-4;
    }
    proto_item_append_text(ti_extensions, " (DiagnosticExtension<%d>)",extensions_length);
    proto_tree_add_item(extensions_tree, hf_reload_length_uint32, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
    while (extensions_offset<extensions_length) {
      int local_increment = dissect_diagnosticextension(tvb, pinfo, extensions_tree, offset+4+local_offset+extensions_offset, extensions_length-extensions_offset);
      if (local_increment <= 0) break;
      extensions_offset += local_increment;
      nExtensions++;
    }
    proto_item_append_text(ti_extensions, " : %d elements", nExtensions);
  }
  local_offset += local_length;
  return local_offset;
}
