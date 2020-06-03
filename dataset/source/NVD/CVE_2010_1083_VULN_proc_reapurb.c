static int CVE_2010_1083_VULN_proc_reapurb(struct dev_state *ps, void __user *arg)
{
	struct async *as = reap_as(ps);
	if (as)
		return processcompl(as, (void __user * __user *)arg);
	if (signal_pending(current))
		return -EINTR;
	return -EIO;
}
