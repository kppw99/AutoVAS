static void CVE_2009_1389_VULN_rtl_set_rx_max_size(void __iomem *ioaddr)
{
	/* Low hurts. Let's disable the filtering. */
	RTL_W16(RxMaxSize, 16383);
}
