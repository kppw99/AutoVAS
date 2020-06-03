 */
int CVE_2012_1184_PATCHED_ast_parse_digest(const char *digest, struct ast_http_digest *d, int request, int pedantic) {
	char *c;
	struct ast_str *str = ast_str_create(16);

	/* table of recognised keywords, and places where they should be copied */
	const struct x {
		const char *key;
		const ast_string_field *field;
	} *i, keys[] = {
		{ "username=", &d->username },
		{ "realm=", &d->realm },
		{ "nonce=", &d->nonce },
		{ "uri=", &d->uri },
		{ "domain=", &d->domain },
		{ "response=", &d->response },
		{ "cnonce=", &d->cnonce },
		{ "opaque=", &d->opaque },
		/* Special cases that cannot be directly copied */
		{ "algorithm=", NULL },
		{ "qop=", NULL },
		{ "nc=", NULL },
		{ NULL, 0 },
	};

	if (ast_strlen_zero(digest) || !d || !str) {
		ast_free(str);
		return -1;
	}

	ast_str_set(&str, 0, "%s", digest);

	c = ast_skip_blanks(ast_str_buffer(str));

	if (strncasecmp(c, "Digest ", strlen("Digest "))) {
		ast_log(LOG_WARNING, "Missing Digest.\n");
		ast_free(str);
		return -1;
	}
	c += strlen("Digest ");

	/* lookup for keys/value pair */
	while (c && *c && *(c = ast_skip_blanks(c))) {
		/* find key */
		for (i = keys; i->key != NULL; i++) {
			char *src, *separator;
			int unescape = 0;
			if (strncasecmp(c, i->key, strlen(i->key)) != 0) {
				continue;
			}

			/* Found. Skip keyword, take text in quotes or up to the separator. */
			c += strlen(i->key);
			if (*c == '"') {
				src = ++c;
				separator = "\"";
				unescape = 1;
			} else {
				src = c;
				separator = ",";
			}
			strsep(&c, separator); /* clear separator and move ptr */
			if (unescape) {
				ast_unescape_c(src);
			}
			if (i->field) {
				ast_string_field_ptr_set(d, i->field, src);
			} else {
				/* Special cases that require additional procesing */
				if (!strcasecmp(i->key, "algorithm=")) {
					if (strcasecmp(src, "MD5")) {
						ast_log(LOG_WARNING, "Digest algorithm: \"%s\" not supported.\n", src);
						ast_free(str);
						return -1;
					}
				} else if (!strcasecmp(i->key, "qop=") && !strcasecmp(src, "auth")) {
					d->qop = 1;
				} else if (!strcasecmp(i->key, "nc=")) {
					unsigned long u;
					if (sscanf(src, "%30lx", &u) != 1) {
						ast_log(LOG_WARNING, "Incorrect Digest nc value: \"%s\".\n", src);
						ast_free(str);
						return -1;
					}
					ast_string_field_set(d, nc, src);
				}
			}
			break;
		}
		if (i->key == NULL) { /* not found, try ',' */
			strsep(&c, ",");
		}
	}
	ast_free(str);

	/* Digest checkout */
	if (ast_strlen_zero(d->realm) || ast_strlen_zero(d->nonce)) {
		/* "realm" and "nonce" MUST be always exist */
		return -1;
	}

	if (!request) {
		/* Additional check for Digest response */
		if (ast_strlen_zero(d->username) || ast_strlen_zero(d->uri) || ast_strlen_zero(d->response)) {
			return -1;
		}

		if (pedantic && d->qop && (ast_strlen_zero(d->cnonce) || ast_strlen_zero(d->nc))) {
			return -1;
		}
	}

	return 0;
}
