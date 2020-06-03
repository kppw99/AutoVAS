static int CVE_2005_3359_VULN___sock_create(int family, int type, int protocol, struct socket **res, int kern)
{
	int i;
	int err;
	struct socket *sock;

	/*
	 *	Check protocol is in range
	 */
	if (family < 0 || family >= NPROTO)
		return -EAFNOSUPPORT;
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;

	/* Compatibility.

	   This uglymoron is moved from INET layer to here to avoid
	   deadlock in module load.
	 */
	if (family == PF_INET && type == SOCK_PACKET) {
		static int warned; 
		if (!warned) {
			warned = 1;
			printk(KERN_INFO "%s uses obsolete (PF_INET,SOCK_PACKET)\n", current->comm);
		}
		family = PF_PACKET;
	}

	err = security_socket_create(family, type, protocol, kern);
	if (err)
		return err;
		
#if defined(CONFIG_KMOD)
	/* Attempt to load a protocol module if the find failed. 
	 * 
	 * 12/09/1996 Marcin: But! this makes REALLY only sense, if the user 
	 * requested real, full-featured networking support upon configuration.
	 * Otherwise module support will break!
	 */
	if (net_families[family]==NULL)
	{
		request_module("net-pf-%d",family);
	}
#endif

	net_family_read_lock();
	if (net_families[family] == NULL) {
		i = -EAFNOSUPPORT;
		goto out;
	}

/*
 *	Allocate the socket and allow the family to set things up. if
 *	the protocol is 0, the family is instructed to select an appropriate
 *	default.
 */

	if (!(sock = sock_alloc())) 
	{
		printk(KERN_WARNING "socket: no more sockets\n");
		i = -ENFILE;		/* Not exactly a match, but its the
					   closest posix thing */
		goto out;
	}

	sock->type  = type;

	/*
	 * We will call the ->create function, that possibly is in a loadable
	 * module, so we have to bump that loadable module refcnt first.
	 */
	i = -EAFNOSUPPORT;
	if (!try_module_get(net_families[family]->owner))
		goto out_release;

	if ((i = net_families[family]->create(sock, protocol)) < 0)
		goto out_module_put;
	/*
	 * Now to bump the refcnt of the [loadable] module that owns this
	 * socket at sock_release time we decrement its refcnt.
	 */
	if (!try_module_get(sock->ops->owner)) {
		sock->ops = NULL;
		goto out_module_put;
	}
	/*
	 * Now that we're done with the ->create function, the [loadable]
	 * module can have its refcnt decremented
	 */
	module_put(net_families[family]->owner);
	*res = sock;
	security_socket_post_create(sock, family, type, protocol, kern);

out:
	net_family_read_unlock();
	return i;
out_module_put:
	module_put(net_families[family]->owner);
out_release:
	sock_release(sock);
	goto out;
}
