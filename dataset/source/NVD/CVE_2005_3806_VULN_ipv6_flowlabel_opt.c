int CVE_2005_3806_VULN_ipv6_flowlabel_opt(struct sock *sk, char __user *optval, int optlen)
{
	int err;
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct in6_flowlabel_req freq;
	struct ipv6_fl_socklist *sfl1=NULL;
	struct ipv6_fl_socklist *sfl, **sflp;
	struct ip6_flowlabel *fl;

	if (optlen < sizeof(freq))
		return -EINVAL;

	if (copy_from_user(&freq, optval, sizeof(freq)))
		return -EFAULT;

	switch (freq.flr_action) {
	case IPV6_FL_A_PUT:
		write_lock_bh(&ip6_sk_fl_lock);
		for (sflp = &np->ipv6_fl_list; (sfl=*sflp)!=NULL; sflp = &sfl->next) {
			if (sfl->fl->label == freq.flr_label) {
				if (freq.flr_label == (np->flow_label&IPV6_FLOWLABEL_MASK))
					np->flow_label &= ~IPV6_FLOWLABEL_MASK;
				*sflp = sfl->next;
				write_unlock_bh(&ip6_sk_fl_lock);
				fl_release(sfl->fl);
				kfree(sfl);
				return 0;
			}
		}
		write_unlock_bh(&ip6_sk_fl_lock);
		return -ESRCH;

	case IPV6_FL_A_RENEW:
		read_lock_bh(&ip6_sk_fl_lock);
		for (sfl = np->ipv6_fl_list; sfl; sfl = sfl->next) {
			if (sfl->fl->label == freq.flr_label) {
				err = fl6_renew(sfl->fl, freq.flr_linger, freq.flr_expires);
				read_unlock_bh(&ip6_sk_fl_lock);
				return err;
			}
		}
		read_unlock_bh(&ip6_sk_fl_lock);

		if (freq.flr_share == IPV6_FL_S_NONE && capable(CAP_NET_ADMIN)) {
			fl = fl_lookup(freq.flr_label);
			if (fl) {
				err = fl6_renew(fl, freq.flr_linger, freq.flr_expires);
				fl_release(fl);
				return err;
			}
		}
		return -ESRCH;

	case IPV6_FL_A_GET:
		if (freq.flr_label & ~IPV6_FLOWLABEL_MASK)
			return -EINVAL;

		fl = fl_create(&freq, optval, optlen, &err);
		if (fl == NULL)
			return err;
		sfl1 = kmalloc(sizeof(*sfl1), GFP_KERNEL);

		if (freq.flr_label) {
			struct ip6_flowlabel *fl1 = NULL;

			err = -EEXIST;
			read_lock_bh(&ip6_sk_fl_lock);
			for (sfl = np->ipv6_fl_list; sfl; sfl = sfl->next) {
				if (sfl->fl->label == freq.flr_label) {
					if (freq.flr_flags&IPV6_FL_F_EXCL) {
						read_unlock_bh(&ip6_sk_fl_lock);
						goto done;
					}
					fl1 = sfl->fl;
					atomic_inc(&fl->users);
					break;
				}
			}
			read_unlock_bh(&ip6_sk_fl_lock);

			if (fl1 == NULL)
				fl1 = fl_lookup(freq.flr_label);
			if (fl1) {
				err = -EEXIST;
				if (freq.flr_flags&IPV6_FL_F_EXCL)
					goto release;
				err = -EPERM;
				if (fl1->share == IPV6_FL_S_EXCL ||
				    fl1->share != fl->share ||
				    fl1->owner != fl->owner)
					goto release;

				err = -EINVAL;
				if (!ipv6_addr_equal(&fl1->dst, &fl->dst) ||
				    ipv6_opt_cmp(fl1->opt, fl->opt))
					goto release;

				err = -ENOMEM;
				if (sfl1 == NULL)
					goto release;
				if (fl->linger > fl1->linger)
					fl1->linger = fl->linger;
				if ((long)(fl->expires - fl1->expires) > 0)
					fl1->expires = fl->expires;
				write_lock_bh(&ip6_sk_fl_lock);
				sfl1->fl = fl1;
				sfl1->next = np->ipv6_fl_list;
				np->ipv6_fl_list = sfl1;
				write_unlock_bh(&ip6_sk_fl_lock);
				fl_free(fl);
				return 0;

release:
				fl_release(fl1);
				goto done;
			}
		}
		err = -ENOENT;
		if (!(freq.flr_flags&IPV6_FL_F_CREATE))
			goto done;

		err = -ENOMEM;
		if (sfl1 == NULL || (err = mem_check(sk)) != 0)
			goto done;

		err = fl_intern(fl, freq.flr_label);
		if (err)
			goto done;

		if (!freq.flr_label) {
			if (copy_to_user(&((struct in6_flowlabel_req __user *) optval)->flr_label,
					 &fl->label, sizeof(fl->label))) {
				/* Intentionally ignore fault. */
			}
		}

		sfl1->fl = fl;
		sfl1->next = np->ipv6_fl_list;
		np->ipv6_fl_list = sfl1;
		return 0;

	default:
		return -EINVAL;
	}

done:
	fl_free(fl);
	kfree(sfl1);
	return err;
}
