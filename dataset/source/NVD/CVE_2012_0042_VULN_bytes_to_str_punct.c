gchar *
CVE_2012_0042_VULN_bytes_to_str_punct(const guint8 *bd, int bd_len, gchar punct) {
  gchar *cur;
  gchar *cur_ptr;
  int truncated = 0;

  if (!punct)
  	return bytes_to_str(bd, bd_len);

  cur=ep_alloc(MAX_BYTE_STR_LEN+3+1);
  if (bd_len <= 0) { cur[0] = '\0'; return cur; }

  if (bd_len > MAX_BYTE_STR_LEN/3) {	/* bd_len > 16 */
     truncated = 1;
     bd_len = MAX_BYTE_STR_LEN/3;
  }

  cur_ptr = bytes_to_hexstr_punct(cur, bd, bd_len, punct); /* max MAX_BYTE_STR_LEN-1 bytes */

  if (truncated) {
    *cur_ptr++ = punct;				/* 1 byte */
    cur_ptr    = g_stpcpy(cur_ptr, "...");	/* 3 bytes */
  }

  *cur_ptr = '\0';
  return cur;
}
