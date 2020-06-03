int
CVE_2010_1087_PATCHED_nfs_wait_on_request(struct nfs_page *req)
{
	return wait_on_bit(&req->wb_flags, PG_BUSY,
			nfs_wait_bit_uninterruptible,
			TASK_UNINTERRUPTIBLE);
}
