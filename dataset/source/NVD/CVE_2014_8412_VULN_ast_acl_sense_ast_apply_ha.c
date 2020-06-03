enum CVE_2014_8412_VULN_ast_acl_sense ast_apply_ha(const struct ast_ha *ha, const struct ast_sockaddr *addr)
{
	/* Start optimistic */
	enum ast_acl_sense res = AST_SENSE_ALLOW;
	const struct ast_ha *current_ha;

	for (current_ha = ha; current_ha; current_ha = current_ha->next) {
		struct ast_sockaddr result;
		struct ast_sockaddr mapped_addr;
		const struct ast_sockaddr *addr_to_use;
#if 0	/* debugging code */
		char iabuf[INET_ADDRSTRLEN];
		char iabuf2[INET_ADDRSTRLEN];
		/* DEBUG */
		ast_copy_string(iabuf, ast_inet_ntoa(sin->sin_addr), sizeof(iabuf));
		ast_copy_string(iabuf2, ast_inet_ntoa(ha->netaddr), sizeof(iabuf2));
		ast_debug(1, "##### Testing %s with %s\n", iabuf, iabuf2);
#endif
		if (ast_sockaddr_is_ipv4(&ha->addr)) {
			if (ast_sockaddr_is_ipv6(addr)) {
				if (ast_sockaddr_is_ipv4_mapped(addr)) {
					/* IPv4 ACLs apply to IPv4-mapped addresses */
					if (!ast_sockaddr_ipv4_mapped(addr, &mapped_addr)) {
						ast_log(LOG_ERROR, "%s provided to ast_sockaddr_ipv4_mapped could not be converted. That shouldn't be possible.\n",
							ast_sockaddr_stringify(addr));
						continue;
					}
					addr_to_use = &mapped_addr;
				} else {
					/* An IPv4 ACL does not apply to an IPv6 address */
					continue;
				}
			} else {
				/* Address is IPv4 and ACL is IPv4. No biggie */
				addr_to_use = addr;
			}
		} else {
			if (ast_sockaddr_is_ipv6(addr) && !ast_sockaddr_is_ipv4_mapped(addr)) {
				addr_to_use = addr;
			} else {
				/* Address is IPv4 or IPv4 mapped but ACL is IPv6. Skip */
				continue;
			}
		}

		/* For each rule, if this address and the netmask = the net address
		   apply the current rule */
		if (ast_sockaddr_apply_netmask(addr_to_use, &current_ha->netmask, &result)) {
			/* Unlikely to happen since we know the address to be IPv4 or IPv6 */
			continue;
		}
		if (!ast_sockaddr_cmp_addr(&result, &current_ha->addr)) {
			res = current_ha->sense;
		}
	}
	return res;
}
