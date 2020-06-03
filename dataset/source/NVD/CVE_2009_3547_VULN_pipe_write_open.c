static int
CVE_2009_3547_VULN_pipe_write_open(struct inode *inode, struct file *filp)
{
	mutex_lock(&inode->i_mutex);
	inode->i_pipe->writers++;
	mutex_unlock(&inode->i_mutex);

	return 0;
}
