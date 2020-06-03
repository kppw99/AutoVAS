static __inline__ void CVE_2013_1979_VULN_scm_set_cred(struct scm_cookie *scm,
				    struct pid *pid, const struct cred *cred)
{
	scm->pid  = get_pid(pid);
	scm->cred = cred ? get_cred(cred) : NULL;
	scm->creds.pid = pid_vnr(pid);
	scm->creds.uid = cred ? cred->euid : INVALID_UID;
	scm->creds.gid = cred ? cred->egid : INVALID_GID;
}
