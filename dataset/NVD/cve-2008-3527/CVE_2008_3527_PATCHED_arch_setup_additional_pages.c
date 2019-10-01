int CVE_2008_3527_PATCHED_arch_setup_additional_pages(struct linux_binprm *bprm, int exstack)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr;
	int ret;

	down_write(&mm->mmap_sem);
	addr = get_unmapped_area(NULL, 0, PAGE_SIZE, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto up_fail;
	}

	/*
	 * MAYWRITE to allow gdb to COW and set breakpoints
	 *
	 * Make sure the vDSO gets into every core dump.
	 * Dumping its contents makes post-mortem fully interpretable later
	 * without matching up the same kernel and hardware config to see
	 * what PC values meant.
	 */
	ret = install_special_mapping(mm, addr, PAGE_SIZE,
				      VM_READ|VM_EXEC|
				      VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC|
				      VM_ALWAYSDUMP,
				      syscall_pages);
	if (ret)
		goto up_fail;

	current->mm->context.vdso = (void *)addr;
	current_thread_info()->sysenter_return =
				    (void *)VDSO_SYM(&SYSENTER_RETURN);
up_fail:
	up_write(&mm->mmap_sem);
	return ret;
}
