int CVE_2004_1151_VULN_sys32_ni_syscall(int call)
{ 
	struct task_struct *me = current;
	static char lastcomm[8];
	if (strcmp(lastcomm, me->comm)) {
	printk(KERN_INFO "IA32 syscall %d from %s not implemented\n", call,
	       current->comm);
		strcpy(lastcomm, me->comm); 
	} 
	return -ENOSYS;	       
} 
