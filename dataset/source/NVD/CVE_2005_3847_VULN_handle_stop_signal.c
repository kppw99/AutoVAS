static void CVE_2005_3847_VULN_handle_stop_signal(int sig, struct task_struct *p)
{
	struct task_struct *t;

	if (p->flags & SIGNAL_GROUP_EXIT)
		/*
		 * The process is in the middle of dying already.
		 */
		return;

	if (sig_kernel_stop(sig)) {
		/*
		 * This is a stop signal.  Remove SIGCONT from all queues.
		 */
		rm_from_queue(sigmask(SIGCONT), &p->signal->shared_pending);
		t = p;
		do {
			rm_from_queue(sigmask(SIGCONT), &t->pending);
			t = next_thread(t);
		} while (t != p);
	} else if (sig == SIGCONT) {
		/*
		 * Remove all stop signals from all queues,
		 * and wake all threads.
		 */
		if (unlikely(p->signal->group_stop_count > 0)) {
			/*
			 * There was a group stop in progress.  We'll
			 * pretend it finished before we got here.  We are
			 * obliged to report it to the parent: if the
			 * SIGSTOP happened "after" this SIGCONT, then it
			 * would have cleared this pending SIGCONT.  If it
			 * happened "before" this SIGCONT, then the parent
			 * got the SIGCHLD about the stop finishing before
			 * the continue happened.  We do the notification
			 * now, and it's as if the stop had finished and
			 * the SIGCHLD was pending on entry to this kill.
			 */
			p->signal->group_stop_count = 0;
			p->signal->flags = SIGNAL_STOP_CONTINUED;
			spin_unlock(&p->sighand->siglock);
			if (p->ptrace & PT_PTRACED)
				do_notify_parent_cldstop(p, p->parent,
							 CLD_STOPPED);
			else
				do_notify_parent_cldstop(
					p->group_leader,
					p->group_leader->real_parent,
							 CLD_STOPPED);
			spin_lock(&p->sighand->siglock);
		}
		rm_from_queue(SIG_KERNEL_STOP_MASK, &p->signal->shared_pending);
		t = p;
		do {
			unsigned int state;
			rm_from_queue(SIG_KERNEL_STOP_MASK, &t->pending);
			
			/*
			 * If there is a handler for SIGCONT, we must make
			 * sure that no thread returns to user mode before
			 * we post the signal, in case it was the only
			 * thread eligible to run the signal handler--then
			 * it must not do anything between resuming and
			 * running the handler.  With the TIF_SIGPENDING
			 * flag set, the thread will pause and acquire the
			 * siglock that we hold now and until we've queued
			 * the pending signal. 
			 *
			 * Wake up the stopped thread _after_ setting
			 * TIF_SIGPENDING
			 */
			state = TASK_STOPPED;
			if (sig_user_defined(t, SIGCONT) && !sigismember(&t->blocked, SIGCONT)) {
				set_tsk_thread_flag(t, TIF_SIGPENDING);
				state |= TASK_INTERRUPTIBLE;
			}
			wake_up_state(t, state);

			t = next_thread(t);
		} while (t != p);

		if (p->signal->flags & SIGNAL_STOP_STOPPED) {
			/*
			 * We were in fact stopped, and are now continued.
			 * Notify the parent with CLD_CONTINUED.
			 */
			p->signal->flags = SIGNAL_STOP_CONTINUED;
			p->signal->group_exit_code = 0;
			spin_unlock(&p->sighand->siglock);
			if (p->ptrace & PT_PTRACED)
				do_notify_parent_cldstop(p, p->parent,
							 CLD_CONTINUED);
			else
				do_notify_parent_cldstop(
					p->group_leader,
					p->group_leader->real_parent,
							 CLD_CONTINUED);
			spin_lock(&p->sighand->siglock);
		} else {
			/*
			 * We are not stopped, but there could be a stop
			 * signal in the middle of being processed after
			 * being removed from the queue.  Clear that too.
			 */
			p->signal->flags = 0;
		}
	} else if (sig == SIGKILL) {
		/*
		 * Make sure that any pending stop signal already dequeued
		 * is undone by the wakeup for SIGKILL.
		 */
		p->signal->flags = 0;
	}
}
