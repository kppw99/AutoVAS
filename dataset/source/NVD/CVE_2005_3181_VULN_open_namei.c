int CVE_2005_3181_VULN_open_namei(const char * pathname, int flag, int mode, struct nameidata *nd)
{
	int acc_mode, error = 0;
	struct path path;
	struct dentry *dir;
	int count = 0;

	acc_mode = ACC_MODE(flag);

	/* Allow the LSM permission hook to distinguish append 
	   access from general write access. */
	if (flag & O_APPEND)
		acc_mode |= MAY_APPEND;

	/* Fill in the open() intent data */
	nd->intent.open.flags = flag;
	nd->intent.open.create_mode = mode;

	/*
	 * The simplest case - just a plain lookup.
	 */
	if (!(flag & O_CREAT)) {
		error = path_lookup(pathname, lookup_flags(flag)|LOOKUP_OPEN, nd);
		if (error)
			return error;
		goto ok;
	}

	/*
	 * Create - we need to know the parent.
	 */
	error = path_lookup(pathname, LOOKUP_PARENT|LOOKUP_OPEN|LOOKUP_CREATE, nd);
	if (error)
		return error;

	/*
	 * We have the parent and last component. First of all, check
	 * that we are not asked to creat(2) an obvious directory - that
	 * will not do.
	 */
	error = -EISDIR;
	if (nd->last_type != LAST_NORM || nd->last.name[nd->last.len])
		goto exit;

	dir = nd->dentry;
	nd->flags &= ~LOOKUP_PARENT;
	down(&dir->d_inode->i_sem);
	path.dentry = __lookup_hash(&nd->last, nd->dentry, nd);
	path.mnt = nd->mnt;

do_last:
	error = PTR_ERR(path.dentry);
	if (IS_ERR(path.dentry)) {
		up(&dir->d_inode->i_sem);
		goto exit;
	}

	/* Negative dentry, just create the file */
	if (!path.dentry->d_inode) {
		if (!IS_POSIXACL(dir->d_inode))
			mode &= ~current->fs->umask;
		error = vfs_create(dir->d_inode, path.dentry, mode, nd);
		up(&dir->d_inode->i_sem);
		dput(nd->dentry);
		nd->dentry = path.dentry;
		if (error)
			goto exit;
		/* Don't check for write permission, don't truncate */
		acc_mode = 0;
		flag &= ~O_TRUNC;
		goto ok;
	}

	/*
	 * It already exists.
	 */
	up(&dir->d_inode->i_sem);

	error = -EEXIST;
	if (flag & O_EXCL)
		goto exit_dput;

	if (__follow_mount(&path)) {
		error = -ELOOP;
		if (flag & O_NOFOLLOW)
			goto exit_dput;
	}
	error = -ENOENT;
	if (!path.dentry->d_inode)
		goto exit_dput;
	if (path.dentry->d_inode->i_op && path.dentry->d_inode->i_op->follow_link)
		goto do_link;

	dput(nd->dentry);
	nd->dentry = path.dentry;
	if (nd->mnt != path.mnt)
		mntput(nd->mnt);
	nd->mnt = path.mnt;
	error = -EISDIR;
	if (path.dentry->d_inode && S_ISDIR(path.dentry->d_inode->i_mode))
		goto exit;
ok:
	error = may_open(nd, acc_mode, flag);
	if (error)
		goto exit;
	return 0;

exit_dput:
	dput(path.dentry);
	if (nd->mnt != path.mnt)
		mntput(path.mnt);
exit:
	path_release(nd);
	return error;

do_link:
	error = -ELOOP;
	if (flag & O_NOFOLLOW)
		goto exit_dput;
	/*
	 * This is subtle. Instead of calling do_follow_link() we do the
	 * thing by hands. The reason is that this way we have zero link_count
	 * and path_walk() (called from ->follow_link) honoring LOOKUP_PARENT.
	 * After that we have the parent and last component, i.e.
	 * we are in the same situation as after the first path_walk().
	 * Well, almost - if the last component is normal we get its copy
	 * stored in nd->last.name and we will have to putname() it when we
	 * are done. Procfs-like symlinks just set LAST_BIND.
	 */
	nd->flags |= LOOKUP_PARENT;
	error = security_inode_follow_link(path.dentry, nd);
	if (error)
		goto exit_dput;
	error = __do_follow_link(&path, nd);
	if (error)
		return error;
	nd->flags &= ~LOOKUP_PARENT;
	if (nd->last_type == LAST_BIND)
		goto ok;
	error = -EISDIR;
	if (nd->last_type != LAST_NORM)
		goto exit;
	if (nd->last.name[nd->last.len]) {
		putname(nd->last.name);
		goto exit;
	}
	error = -ELOOP;
	if (count++==32) {
		putname(nd->last.name);
		goto exit;
	}
	dir = nd->dentry;
	down(&dir->d_inode->i_sem);
	path.dentry = __lookup_hash(&nd->last, nd->dentry, nd);
	path.mnt = nd->mnt;
	putname(nd->last.name);
	goto do_last;
}
