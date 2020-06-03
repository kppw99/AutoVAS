void CVE_2011_0710_VULN_task_show_regs(struct seq_file *m, struct task_struct *task)
{
	struct pt_regs *regs;

	regs = task_pt_regs(task);
	seq_printf(m, "task: %p, ksp: %p\n",
		       task, (void *)task->thread.ksp);
	seq_printf(m, "User PSW : %p %p\n",
		       (void *) regs->psw.mask, (void *)regs->psw.addr);

	seq_printf(m, "User GPRS: " FOURLONG,
			  regs->gprs[0], regs->gprs[1],
			  regs->gprs[2], regs->gprs[3]);
	seq_printf(m, "           " FOURLONG,
			  regs->gprs[4], regs->gprs[5],
			  regs->gprs[6], regs->gprs[7]);
	seq_printf(m, "           " FOURLONG,
			  regs->gprs[8], regs->gprs[9],
			  regs->gprs[10], regs->gprs[11]);
	seq_printf(m, "           " FOURLONG,
			  regs->gprs[12], regs->gprs[13],
			  regs->gprs[14], regs->gprs[15]);
	seq_printf(m, "User ACRS: %08x %08x %08x %08x\n",
			  task->thread.acrs[0], task->thread.acrs[1],
			  task->thread.acrs[2], task->thread.acrs[3]);
	seq_printf(m, "           %08x %08x %08x %08x\n",
			  task->thread.acrs[4], task->thread.acrs[5],
			  task->thread.acrs[6], task->thread.acrs[7]);
	seq_printf(m, "           %08x %08x %08x %08x\n",
			  task->thread.acrs[8], task->thread.acrs[9],
			  task->thread.acrs[10], task->thread.acrs[11]);
	seq_printf(m, "           %08x %08x %08x %08x\n",
			  task->thread.acrs[12], task->thread.acrs[13],
			  task->thread.acrs[14], task->thread.acrs[15]);
}
