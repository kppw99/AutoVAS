static int CVE_2007_1000_PATCHED_ipv6_getsockopt_sticky(struct sock *sk, struct ipv6_txoptions *opt,
				  char __user *optval, int len)
{
	struct ipv6_opt_hdr *hdr;

	if (!opt || !opt->hopopt)
		return 0;

	hdr = opt->hopopt;

	len = min_t(int, len, ipv6_optlen(hdr));
	if (copy_to_user(optval, hdr, len))
		return -EFAULT;
	return len;
}
