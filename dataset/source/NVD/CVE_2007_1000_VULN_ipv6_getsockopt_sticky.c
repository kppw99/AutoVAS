static int CVE_2007_1000_VULN_ipv6_getsockopt_sticky(struct sock *sk, struct ipv6_opt_hdr *hdr,
				  char __user *optval, int len)
{
	if (!hdr)
		return 0;
	len = min_t(int, len, ipv6_optlen(hdr));
	if (copy_to_user(optval, hdr, ipv6_optlen(hdr)))
		return -EFAULT;
	return len;
}
