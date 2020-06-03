int CVE_2009_1046_VULN_set_selection(const struct tiocl_selection __user *sel, struct tty_struct *tty)
{
	struct vc_data *vc = vc_cons[fg_console].d;
	int sel_mode, new_sel_start, new_sel_end, spc;
	char *bp, *obp;
	int i, ps, pe, multiplier;
	u16 c;
	struct kbd_struct *kbd = kbd_table + fg_console;

	poke_blanked_console();

	{ unsigned short xs, ys, xe, ye;

	  if (!access_ok(VERIFY_READ, sel, sizeof(*sel)))
		return -EFAULT;
	  __get_user(xs, &sel->xs);
	  __get_user(ys, &sel->ys);
	  __get_user(xe, &sel->xe);
	  __get_user(ye, &sel->ye);
	  __get_user(sel_mode, &sel->sel_mode);
	  xs--; ys--; xe--; ye--;
	  xs = limit(xs, vc->vc_cols - 1);
	  ys = limit(ys, vc->vc_rows - 1);
	  xe = limit(xe, vc->vc_cols - 1);
	  ye = limit(ye, vc->vc_rows - 1);
	  ps = ys * vc->vc_size_row + (xs << 1);
	  pe = ye * vc->vc_size_row + (xe << 1);

	  if (sel_mode == TIOCL_SELCLEAR) {
	      /* useful for screendump without selection highlights */
	      clear_selection();
	      return 0;
	  }

	  if (mouse_reporting() && (sel_mode & TIOCL_SELMOUSEREPORT)) {
	      mouse_report(tty, sel_mode & TIOCL_SELBUTTONMASK, xs, ys);
	      return 0;
	  }
        }

	if (ps > pe)	/* make sel_start <= sel_end */
	{
		int tmp = ps;
		ps = pe;
		pe = tmp;
	}

	if (sel_cons != vc_cons[fg_console].d) {
		clear_selection();
		sel_cons = vc_cons[fg_console].d;
	}
	use_unicode = kbd && kbd->kbdmode == VC_UNICODE;

	switch (sel_mode)
	{
		case TIOCL_SELCHAR:	/* character-by-character selection */
			new_sel_start = ps;
			new_sel_end = pe;
			break;
		case TIOCL_SELWORD:	/* word-by-word selection */
			spc = isspace(sel_pos(ps));
			for (new_sel_start = ps; ; ps -= 2)
			{
				if ((spc && !isspace(sel_pos(ps))) ||
				    (!spc && !inword(sel_pos(ps))))
					break;
				new_sel_start = ps;
				if (!(ps % vc->vc_size_row))
					break;
			}
			spc = isspace(sel_pos(pe));
			for (new_sel_end = pe; ; pe += 2)
			{
				if ((spc && !isspace(sel_pos(pe))) ||
				    (!spc && !inword(sel_pos(pe))))
					break;
				new_sel_end = pe;
				if (!((pe + 2) % vc->vc_size_row))
					break;
			}
			break;
		case TIOCL_SELLINE:	/* line-by-line selection */
			new_sel_start = ps - ps % vc->vc_size_row;
			new_sel_end = pe + vc->vc_size_row
				    - pe % vc->vc_size_row - 2;
			break;
		case TIOCL_SELPOINTER:
			highlight_pointer(pe);
			return 0;
		default:
			return -EINVAL;
	}

	/* remove the pointer */
	highlight_pointer(-1);

	/* select to end of line if on trailing space */
	if (new_sel_end > new_sel_start &&
		!atedge(new_sel_end, vc->vc_size_row) &&
		isspace(sel_pos(new_sel_end))) {
		for (pe = new_sel_end + 2; ; pe += 2)
			if (!isspace(sel_pos(pe)) ||
			    atedge(pe, vc->vc_size_row))
				break;
		if (isspace(sel_pos(pe)))
			new_sel_end = pe;
	}
	if (sel_start == -1)	/* no current selection */
		highlight(new_sel_start, new_sel_end);
	else if (new_sel_start == sel_start)
	{
		if (new_sel_end == sel_end)	/* no action required */
			return 0;
		else if (new_sel_end > sel_end)	/* extend to right */
			highlight(sel_end + 2, new_sel_end);
		else				/* contract from right */
			highlight(new_sel_end + 2, sel_end);
	}
	else if (new_sel_end == sel_end)
	{
		if (new_sel_start < sel_start)	/* extend to left */
			highlight(new_sel_start, sel_start - 2);
		else				/* contract from left */
			highlight(sel_start, new_sel_start - 2);
	}
	else	/* some other case; start selection from scratch */
	{
		clear_selection();
		highlight(new_sel_start, new_sel_end);
	}
	sel_start = new_sel_start;
	sel_end = new_sel_end;

	/* Allocate a new buffer before freeing the old one ... */
	multiplier = use_unicode ? 3 : 1;  /* chars can take up to 3 bytes */
	bp = kmalloc((sel_end-sel_start)/2*multiplier+1, GFP_KERNEL);
	if (!bp) {
		printk(KERN_WARNING "selection: kmalloc() failed\n");
		clear_selection();
		return -ENOMEM;
	}
	kfree(sel_buffer);
	sel_buffer = bp;

	obp = bp;
	for (i = sel_start; i <= sel_end; i += 2) {
		c = sel_pos(i);
		if (use_unicode)
			bp += store_utf8(c, bp);
		else
			*bp++ = c;
		if (!isspace(c))
			obp = bp;
		if (! ((i + 2) % vc->vc_size_row)) {
			/* strip trailing blanks from line and add newline,
			   unless non-space at end of line. */
			if (obp != bp) {
				bp = obp;
				*bp++ = '\r';
			}
			obp = bp;
		}
	}
	sel_buffer_lth = bp - sel_buffer;
	return 0;
}
