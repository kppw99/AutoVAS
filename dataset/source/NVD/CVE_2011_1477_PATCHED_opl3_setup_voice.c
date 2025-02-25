static void CVE_2011_1477_PATCHED_opl3_setup_voice(int dev, int voice, int chn)
{
	struct channel_info *info;

	if (voice < 0 || voice >= devc->nr_voice)
		return;

	if (chn < 0 || chn > 15)
		return;

	info = &synth_devs[dev]->chn_info[chn];

	opl3_set_instr(dev, voice, info->pgm_num);

	devc->voc[voice].bender = 0;
	devc->voc[voice].bender_range = info->bender_range;
	devc->voc[voice].volume = info->controllers[CTL_MAIN_VOLUME];
	devc->voc[voice].panning = (info->controllers[CTL_PAN] * 2) - 128;
}
