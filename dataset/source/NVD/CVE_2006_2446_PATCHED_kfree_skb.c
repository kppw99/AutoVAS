static inline void CVE_2006_2446_PATCHED_kfree_skb(struct sk_buff *skb)
{
	if (likely(atomic_read(&skb->users) == 1))
		smp_rmb();
	else if (likely(!atomic_dec_and_test(&skb->users)))
		return;
	__kfree_skb(skb);
}
