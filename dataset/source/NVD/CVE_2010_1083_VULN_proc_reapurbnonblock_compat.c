static int CVE_2010_1083_VULN_proc_reapurbnonblock_compat(struct dev_state *ps, void __user *arg)
{
	struct async *as;

	if (!(as = async_getcompleted(ps)))
		return -EAGAIN;
	return processcompl_compat(as, (void __user * __user *)arg);
}
