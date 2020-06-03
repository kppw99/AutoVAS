struct dentry *
CVE_2012_1090_VULN_cifs_lookup(struct inode *parent_dir_inode, struct dentry *direntry,
	    struct nameidata *nd)
{
	int xid;
	int rc = 0; /* to get around spurious gcc warning, set to zero here */
	__u32 oplock = 0;
	__u16 fileHandle = 0;
	bool posix_open = false;
	struct cifs_sb_info *cifs_sb;
	struct cifsTconInfo *pTcon;
	struct cifsFileInfo *cfile;
	struct inode *newInode = NULL;
	char *full_path = NULL;
	struct file *filp;

	xid = GetXid();

	cFYI(1, "parent inode = 0x%p name is: %s and dentry = 0x%p",
	      parent_dir_inode, direntry->d_name.name, direntry);

	/* check whether path exists */

	cifs_sb = CIFS_SB(parent_dir_inode->i_sb);
	pTcon = cifs_sb->tcon;

	/*
	 * Don't allow the separator character in a path component.
	 * The VFS will not allow "/", but "\" is allowed by posix.
	 */
	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_POSIX_PATHS)) {
		int i;
		for (i = 0; i < direntry->d_name.len; i++)
			if (direntry->d_name.name[i] == '\\') {
				cFYI(1, "Invalid file name");
				FreeXid(xid);
				return ERR_PTR(-EINVAL);
			}
	}

	/*
	 * O_EXCL: optimize away the lookup, but don't hash the dentry. Let
	 * the VFS handle the create.
	 */
	if (nd && (nd->flags & LOOKUP_EXCL)) {
		d_instantiate(direntry, NULL);
		return NULL;
	}

	/* can not grab the rename sem here since it would
	deadlock in the cases (beginning of sys_rename itself)
	in which we already have the sb rename sem */
	full_path = build_path_from_dentry(direntry);
	if (full_path == NULL) {
		FreeXid(xid);
		return ERR_PTR(-ENOMEM);
	}

	if (direntry->d_inode != NULL) {
		cFYI(1, "non-NULL inode in lookup");
	} else {
		cFYI(1, "NULL inode in lookup");
	}
	cFYI(1, "Full path: %s inode = 0x%p", full_path, direntry->d_inode);

	/* Posix open is only called (at lookup time) for file create now.
	 * For opens (rather than creates), because we do not know if it
	 * is a file or directory yet, and current Samba no longer allows
	 * us to do posix open on dirs, we could end up wasting an open call
	 * on what turns out to be a dir. For file opens, we wait to call posix
	 * open till cifs_open.  It could be added here (lookup) in the future
	 * but the performance tradeoff of the extra network request when EISDIR
	 * or EACCES is returned would have to be weighed against the 50%
	 * reduction in network traffic in the other paths.
	 */
	if (pTcon->unix_ext) {
		if (nd && !(nd->flags & (LOOKUP_PARENT | LOOKUP_DIRECTORY)) &&
		     (nd->flags & LOOKUP_OPEN) && !pTcon->broken_posix_open &&
		     (nd->intent.open.flags & O_CREAT)) {
			rc = cifs_posix_open(full_path, &newInode,
					parent_dir_inode->i_sb,
					nd->intent.open.create_mode,
					nd->intent.open.flags, &oplock,
					&fileHandle, xid);
			/*
			 * The check below works around a bug in POSIX
			 * open in samba versions 3.3.1 and earlier where
			 * open could incorrectly fail with invalid parameter.
			 * If either that or op not supported returned, follow
			 * the normal lookup.
			 */
			if ((rc == 0) || (rc == -ENOENT))
				posix_open = true;
			else if ((rc == -EINVAL) || (rc != -EOPNOTSUPP))
				pTcon->broken_posix_open = true;
		}
		if (!posix_open)
			rc = cifs_get_inode_info_unix(&newInode, full_path,
						parent_dir_inode->i_sb, xid);
	} else
		rc = cifs_get_inode_info(&newInode, full_path, NULL,
				parent_dir_inode->i_sb, xid, NULL);

	if ((rc == 0) && (newInode != NULL)) {
		if (pTcon->nocase)
			direntry->d_op = &cifs_ci_dentry_ops;
		else
			direntry->d_op = &cifs_dentry_ops;
		d_add(direntry, newInode);
		if (posix_open) {
			filp = lookup_instantiate_filp(nd, direntry,
						       generic_file_open);
			if (IS_ERR(filp)) {
				rc = PTR_ERR(filp);
				CIFSSMBClose(xid, pTcon, fileHandle);
				goto lookup_out;
			}

			cfile = cifs_new_fileinfo(newInode, fileHandle, filp,
						  nd->path.mnt,
						  nd->intent.open.flags);
			if (cfile == NULL) {
				fput(filp);
				CIFSSMBClose(xid, pTcon, fileHandle);
				rc = -ENOMEM;
				goto lookup_out;
			}
		}
		/* since paths are not looked up by component - the parent
		   directories are presumed to be good here */
		renew_parental_timestamps(direntry);

	} else if (rc == -ENOENT) {
		rc = 0;
		direntry->d_time = jiffies;
		if (pTcon->nocase)
			direntry->d_op = &cifs_ci_dentry_ops;
		else
			direntry->d_op = &cifs_dentry_ops;
		d_add(direntry, NULL);
	/*	if it was once a directory (but how can we tell?) we could do
		shrink_dcache_parent(direntry); */
	} else if (rc != -EACCES) {
		cERROR(1, "Unexpected lookup error %d", rc);
		/* We special case check for Access Denied - since that
		is a common return code */
	}

lookup_out:
	kfree(full_path);
	FreeXid(xid);
	return ERR_PTR(rc);
}
