void CVE_2006_2445_VULN_run_posix_cpu_timers(struct task_struct *tsk)
{
	LIST_HEAD(firing);
	struct k_itimer *timer, *next;

	BUG_ON(!irqs_disabled());

#define UNEXPIRED(clock) \
		(cputime_eq(tsk->it_##clock##_expires, cputime_zero) || \
		 cputime_lt(clock##_ticks(tsk), tsk->it_##clock##_expires))

	if (UNEXPIRED(prof) && UNEXPIRED(virt) &&
	    (tsk->it_sched_expires == 0 ||
	     tsk->sched_time < tsk->it_sched_expires))
		return;

#undef	UNEXPIRED

	BUG_ON(tsk->exit_state);

	/*
	 * Double-check with locks held.
	 */
	read_lock(&tasklist_lock);
	spin_lock(&tsk->sighand->siglock);

	/*
	 * Here we take off tsk->cpu_timers[N] and tsk->signal->cpu_timers[N]
	 * all the timers that are firing, and put them on the firing list.
	 */
	check_thread_timers(tsk, &firing);
	check_process_timers(tsk, &firing);

	/*
	 * We must release these locks before taking any timer's lock.
	 * There is a potential race with timer deletion here, as the
	 * siglock now protects our private firing list.  We have set
	 * the firing flag in each timer, so that a deletion attempt
	 * that gets the timer lock before we do will give it up and
	 * spin until we've taken care of that timer below.
	 */
	spin_unlock(&tsk->sighand->siglock);
	read_unlock(&tasklist_lock);

	/*
	 * Now that all the timers on our list have the firing flag,
	 * noone will touch their list entries but us.  We'll take
	 * each timer's lock before clearing its firing flag, so no
	 * timer call will interfere.
	 */
	list_for_each_entry_safe(timer, next, &firing, it.cpu.entry) {
		int firing;
		spin_lock(&timer->it_lock);
		list_del_init(&timer->it.cpu.entry);
		firing = timer->it.cpu.firing;
		timer->it.cpu.firing = 0;
		/*
		 * The firing flag is -1 if we collided with a reset
		 * of the timer, which already reported this
		 * almost-firing as an overrun.  So don't generate an event.
		 */
		if (likely(firing >= 0)) {
			cpu_timer_fire(timer);
		}
		spin_unlock(&timer->it_lock);
	}
}
