int CVE_2015_6654_VULN_xenmem_add_to_physmap_one(
    struct domain *d,
    unsigned int space,
    domid_t foreign_domid,
    unsigned long idx,
    xen_pfn_t gpfn)
{
    unsigned long mfn = 0;
    int rc;
    p2m_type_t t;

    switch ( space )
    {
    case XENMAPSPACE_grant_table:
        spin_lock(&d->grant_table->lock);

        if ( d->grant_table->gt_version == 0 )
            d->grant_table->gt_version = 1;

        if ( d->grant_table->gt_version == 2 &&
                (idx & XENMAPIDX_grant_table_status) )
        {
            idx &= ~XENMAPIDX_grant_table_status;
            if ( idx < nr_status_frames(d->grant_table) )
                mfn = virt_to_mfn(d->grant_table->status[idx]);
            else
                return -EINVAL;
        }
        else
        {
            if ( (idx >= nr_grant_frames(d->grant_table)) &&
                    (idx < max_nr_grant_frames) )
                gnttab_grow_table(d, idx + 1);

            if ( idx < nr_grant_frames(d->grant_table) )
                mfn = virt_to_mfn(d->grant_table->shared_raw[idx]);
            else
                return -EINVAL;
        }
        
        d->arch.grant_table_gpfn[idx] = gpfn;

        t = p2m_ram_rw;

        spin_unlock(&d->grant_table->lock);
        break;
    case XENMAPSPACE_shared_info:
        if ( idx != 0 )
            return -EINVAL;

        mfn = virt_to_mfn(d->shared_info);
        t = p2m_ram_rw;

        break;
    case XENMAPSPACE_gmfn_foreign:
    {
        struct domain *od;
        struct page_info *page;
        p2m_type_t p2mt;
        od = rcu_lock_domain_by_any_id(foreign_domid);
        if ( od == NULL )
            return -ESRCH;

        if ( od == d )
        {
            rcu_unlock_domain(od);
            return -EINVAL;
        }

        rc = xsm_map_gmfn_foreign(XSM_TARGET, d, od);
        if ( rc )
        {
            rcu_unlock_domain(od);
            return rc;
        }

        /* Take reference to the foreign domain page.
         * Reference will be released in XENMEM_remove_from_physmap */
        page = get_page_from_gfn(od, idx, &p2mt, P2M_ALLOC);
        if ( !page )
        {
            dump_p2m_lookup(od, pfn_to_paddr(idx));
            rcu_unlock_domain(od);
            return -EINVAL;
        }

        if ( !p2m_is_ram(p2mt) )
        {
            put_page(page);
            rcu_unlock_domain(od);
            return -EINVAL;
        }

        mfn = page_to_mfn(page);
        t = p2m_map_foreign;

        rcu_unlock_domain(od);
        break;
    }

    default:
        return -ENOSYS;
    }

    /* Map at new location. */
    rc = guest_physmap_add_entry(d, gpfn, mfn, 0, t);

    return rc;
}
