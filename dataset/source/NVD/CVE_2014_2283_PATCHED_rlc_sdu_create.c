static struct rlc_sdu *
CVE_2014_2283_PATCHED_rlc_sdu_create(void)
{
	struct rlc_sdu *sdu;

       sdu = g_malloc0(sizeof(struct rlc_sdu));
	return sdu;
}
