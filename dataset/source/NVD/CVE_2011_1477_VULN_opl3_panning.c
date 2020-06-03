static void CVE_2011_1477_VULN_opl3_panning(int dev, int voice, int value)
{
	devc->voc[voice].panning = value;
}
