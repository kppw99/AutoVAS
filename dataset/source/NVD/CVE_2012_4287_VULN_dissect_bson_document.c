static int
CVE_2012_4287_VULN_dissect_bson_document(tvbuff_t *tvb, guint offset, proto_tree *tree, int hf_mongo_doc)
{
  gint32 document_length;
  guint final_offset;
  proto_item *ti, *elements, *element, *objectid, *js_code, *js_scope;
  proto_tree *doc_tree, *elements_tree, *element_sub_tree, *objectid_sub_tree, *js_code_sub_tree, *js_scope_sub_tree;

  document_length = tvb_get_letohl(tvb, offset);
  if (document_length == 5) {
    /* document with length 5 is an empty document */
    /* don't display the element subtree */
    proto_tree_add_item(tree, hf_mongo_document_empty, tvb, offset, document_length, ENC_NA);
    return document_length;
  }

  ti = proto_tree_add_item(tree, hf_mongo_doc, tvb, offset, document_length, ENC_NA);
  doc_tree = proto_item_add_subtree(ti, ett_mongo_doc);

  proto_tree_add_item(doc_tree, hf_mongo_document_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  final_offset = offset + document_length;
  offset += 4;

  elements = proto_tree_add_item(doc_tree, hf_mongo_elements, tvb, offset, document_length-5, ENC_NA);
  elements_tree = proto_item_add_subtree(elements, ett_mongo_elements);

  do {
    /* Read document elements */
    guint8 e_type = -1;  /* Element type */
    gint str_len = -1;   /* String length */
    gint e_len = -1;     /* Element length */
    gint doc_len = -1;   /* Document length */

    e_type = tvb_get_guint8(tvb, offset);
    tvb_get_ephemeral_stringz(tvb, offset+1, &str_len);

    element = proto_tree_add_item(elements_tree, hf_mongo_element_name, tvb, offset+1, str_len-1, ENC_UTF_8|ENC_NA);
    element_sub_tree = proto_item_add_subtree(element, ett_mongo_element);
    proto_tree_add_item(element_sub_tree, hf_mongo_element_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    offset += str_len+1;

    switch(e_type) {
      case BSON_ELEMENT_TYPE_DOUBLE:
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        break;
      case BSON_ELEMENT_TYPE_STRING:
      case BSON_ELEMENT_TYPE_JS_CODE:
      case BSON_ELEMENT_TYPE_SYMBOL:
        str_len = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_string_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_string, tvb, offset+4, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len+4;
        break;
      case BSON_ELEMENT_TYPE_DOC:
      case BSON_ELEMENT_TYPE_ARRAY:
        offset += CVE_2012_4287_VULN_dissect_bson_document(tvb, offset, element_sub_tree, hf_mongo_document);
        break;
      case BSON_ELEMENT_TYPE_BINARY:
        e_len = tvb_get_letohl(tvb, offset);
        /* TODO - Add functions to decode various binary subtypes */
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_binary_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_binary, tvb, offset+5, e_len, ENC_NA);
        offset += e_len+5;
        break;
      case BSON_ELEMENT_TYPE_UNDEF:
      case BSON_ELEMENT_TYPE_NULL:
      case BSON_ELEMENT_TYPE_MIN_KEY:
      case BSON_ELEMENT_TYPE_MAX_KEY:
        /* Nothing to do, as there is no element content */
        break;
      case BSON_ELEMENT_TYPE_OBJ_ID:
        objectid = proto_tree_add_item(element_sub_tree, hf_mongo_element_value_objectid, tvb, offset, 12, ENC_NA);
        objectid_sub_tree = proto_item_add_subtree(objectid, ett_mongo_objectid);
        /* Unlike most BSON elements, parts of ObjectID are stored Big Endian, so they can be compared bit by bit */
        proto_tree_add_item(objectid_sub_tree, hf_mongo_element_value_objectid_time, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(objectid_sub_tree, hf_mongo_element_value_objectid_machine, tvb, offset+4, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(objectid_sub_tree, hf_mongo_element_value_objectid_pid, tvb, offset+7, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(objectid_sub_tree, hf_mongo_element_value_objectid_inc, tvb, offset+9, 3, ENC_BIG_ENDIAN);
        offset += 12;
        break;
      case BSON_ELEMENT_TYPE_BOOL:
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_boolean, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;
      case BSON_ELEMENT_TYPE_REGEX:
        /* regex pattern */
        tvb_get_ephemeral_stringz(tvb, offset, &str_len);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_regex_pattern, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        /* regex options */
        tvb_get_ephemeral_stringz(tvb, offset, &str_len);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_regex_options, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        break;
      case BSON_ELEMENT_TYPE_DB_PTR:
        str_len = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_string_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_string, tvb, offset+4, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_db_ptr, tvb, offset, 12, ENC_NA);
        offset += 12;
        break;
      case BSON_ELEMENT_TYPE_JS_CODE_SCOPE:
        /* code_w_s ::= int32 string document */
        proto_tree_add_item(element_sub_tree, hf_mongo_element_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        e_len = tvb_get_letohl(tvb, offset);
        offset += 4;
        str_len = tvb_get_letohl(tvb, offset);
        js_code = proto_tree_add_item(element_sub_tree, hf_mongo_element_value_js_code, tvb, offset, str_len+4, ENC_NA);
        js_code_sub_tree = proto_item_add_subtree(js_code, ett_mongo_code);
        proto_tree_add_item(js_code_sub_tree, hf_mongo_element_value_string_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(js_code_sub_tree, hf_mongo_element_value_string, tvb, offset+4, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len+4;
        doc_len = e_len - (str_len + 8);
        js_scope = proto_tree_add_item(element_sub_tree, hf_mongo_element_value_js_scope, tvb, offset, doc_len, ENC_NA);
        js_scope_sub_tree = proto_item_add_subtree(js_scope, ett_mongo_code);
        offset += CVE_2012_4287_VULN_dissect_bson_document(tvb, offset, js_scope_sub_tree, hf_mongo_document);
        break;
      case BSON_ELEMENT_TYPE_INT32:
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_int32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;
      case BSON_ELEMENT_TYPE_DATETIME:
      case BSON_ELEMENT_TYPE_TIMESTAMP:
        /* TODO Implement routine to convert datetime & timestamp values to UTC date/time */
        /* for now, simply display the integer value */
      case BSON_ELEMENT_TYPE_INT64:
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_int64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        break;
      default:
        break;
    }  /* end switch() */
  } while (offset < final_offset-1);

  return document_length;
}
