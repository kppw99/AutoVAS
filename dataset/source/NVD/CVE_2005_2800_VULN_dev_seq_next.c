static void * CVE_2005_2800_VULN_dev_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct sg_proc_deviter * it = (struct sg_proc_deviter *) v;

	*pos = ++it->index;
	return (it->index < it->max) ? it : NULL;
}
