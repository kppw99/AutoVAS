static int CVE_2009_2909_VULN_ax25_setsockopt(struct socket *sock, int level, int optname,
	char __user *optval, int optlen)
{
	struct sock *sk = sock->sk;
	ax25_cb *ax25;
	struct net_device *dev;
	char devname[IFNAMSIZ];
	int opt, res = 0;

	if (level != SOL_AX25)
		return -ENOPROTOOPT;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(opt, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);
	ax25 = ax25_sk(sk);

	switch (optname) {
	case AX25_WINDOW:
		if (ax25->modulus == AX25_MODULUS) {
			if (opt < 1 || opt > 7) {
				res = -EINVAL;
				break;
			}
		} else {
			if (opt < 1 || opt > 63) {
				res = -EINVAL;
				break;
			}
		}
		ax25->window = opt;
		break;

	case AX25_T1:
		if (opt < 1) {
			res = -EINVAL;
			break;
		}
		ax25->rtt = (opt * HZ) >> 1;
		ax25->t1  = opt * HZ;
		break;

	case AX25_T2:
		if (opt < 1) {
			res = -EINVAL;
			break;
		}
		ax25->t2 = opt * HZ;
		break;

	case AX25_N2:
		if (opt < 1 || opt > 31) {
			res = -EINVAL;
			break;
		}
		ax25->n2 = opt;
		break;

	case AX25_T3:
		if (opt < 1) {
			res = -EINVAL;
			break;
		}
		ax25->t3 = opt * HZ;
		break;

	case AX25_IDLE:
		if (opt < 0) {
			res = -EINVAL;
			break;
		}
		ax25->idle = opt * 60 * HZ;
		break;

	case AX25_BACKOFF:
		if (opt < 0 || opt > 2) {
			res = -EINVAL;
			break;
		}
		ax25->backoff = opt;
		break;

	case AX25_EXTSEQ:
		ax25->modulus = opt ? AX25_EMODULUS : AX25_MODULUS;
		break;

	case AX25_PIDINCL:
		ax25->pidincl = opt ? 1 : 0;
		break;

	case AX25_IAMDIGI:
		ax25->iamdigi = opt ? 1 : 0;
		break;

	case AX25_PACLEN:
		if (opt < 16 || opt > 65535) {
			res = -EINVAL;
			break;
		}
		ax25->paclen = opt;
		break;

	case SO_BINDTODEVICE:
		if (optlen > IFNAMSIZ)
			optlen=IFNAMSIZ;
		if (copy_from_user(devname, optval, optlen)) {
		res = -EFAULT;
			break;
		}

		dev = dev_get_by_name(&init_net, devname);
		if (dev == NULL) {
			res = -ENODEV;
			break;
		}

		if (sk->sk_type == SOCK_SEQPACKET &&
		   (sock->state != SS_UNCONNECTED ||
		    sk->sk_state == TCP_LISTEN)) {
			res = -EADDRNOTAVAIL;
			dev_put(dev);
			break;
		}

		ax25->ax25_dev = ax25_dev_ax25dev(dev);
		ax25_fillin_cb(ax25, ax25->ax25_dev);
		break;

	default:
		res = -ENOPROTOOPT;
	}
	release_sock(sk);

	return res;
}
