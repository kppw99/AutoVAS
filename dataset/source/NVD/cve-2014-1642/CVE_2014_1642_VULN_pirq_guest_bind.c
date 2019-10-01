int CVE_2014_1642_VULN_pirq_guest_bind(struct vcpu *v, struct pirq *pirq, int will_share)
{
    unsigned int        irq;
    struct irq_desc         *desc;
    irq_guest_action_t *action, *newaction = NULL;
    int                 rc = 0;

    WARN_ON(!spin_is_locked(&v->domain->event_lock));
    BUG_ON(!local_irq_is_enabled());

 retry:
    desc = pirq_spin_lock_irq_desc(pirq, NULL);
    if ( desc == NULL )
    {
        rc = -EINVAL;
        goto out;
    }

    action = (irq_guest_action_t *)desc->action;
    irq = desc - irq_desc;

    if ( !(desc->status & IRQ_GUEST) )
    {
        if ( desc->action != NULL )
        {
            printk(XENLOG_G_INFO
                   "Cannot bind IRQ%d to dom%d. In use by '%s'.\n",
                   pirq->pirq, v->domain->domain_id, desc->action->name);
            rc = -EBUSY;
            goto unlock_out;
        }

        if ( newaction == NULL )
        {
            spin_unlock_irq(&desc->lock);
            if ( (newaction = xmalloc(irq_guest_action_t)) != NULL &&
                 zalloc_cpumask_var(&newaction->cpu_eoi_map) )
                goto retry;
            xfree(newaction);
            printk(XENLOG_G_INFO
                   "Cannot bind IRQ%d to dom%d. Out of memory.\n",
                   pirq->pirq, v->domain->domain_id);
            rc = -ENOMEM;
            goto out;
        }

        action = newaction;
        desc->action = (struct irqaction *)action;
        newaction = NULL;

        action->nr_guests   = 0;
        action->in_flight   = 0;
        action->shareable   = will_share;
        action->ack_type    = pirq_acktype(v->domain, pirq->pirq);
        init_timer(&action->eoi_timer, irq_guest_eoi_timer_fn, desc, 0);

        desc->status |= IRQ_GUEST;
        desc->status &= ~IRQ_DISABLED;
        desc->handler->startup(desc);

        /* Attempt to bind the interrupt target to the correct CPU. */
        if ( !opt_noirqbalance && (desc->handler->set_affinity != NULL) )
            desc->handler->set_affinity(desc, cpumask_of(v->processor));
    }
    else if ( !will_share || !action->shareable )
    {
        printk(XENLOG_G_INFO "Cannot bind IRQ%d to dom%d. %s.\n",
               pirq->pirq, v->domain->domain_id,
               will_share ? "Others do not share"
                          : "Will not share with others");
        rc = -EBUSY;
        goto unlock_out;
    }
    else if ( action->nr_guests == 0 )
    {
        /*
         * Indicates that an ACKTYPE_EOI interrupt is being released.
         * Wait for that to happen before continuing.
         */
        ASSERT(action->ack_type == ACKTYPE_EOI);
        ASSERT(desc->status & IRQ_DISABLED);
        spin_unlock_irq(&desc->lock);
        cpu_relax();
        goto retry;
    }

    if ( action->nr_guests == IRQ_MAX_GUESTS )
    {
        printk(XENLOG_G_INFO "Cannot bind IRQ%d to dom%d. "
               "Already at max share.\n",
               pirq->pirq, v->domain->domain_id);
        rc = -EBUSY;
        goto unlock_out;
    }

    action->guest[action->nr_guests++] = v->domain;

    if ( action->ack_type != ACKTYPE_NONE )
        set_pirq_eoi(v->domain, pirq->pirq);
    else
        clear_pirq_eoi(v->domain, pirq->pirq);

 unlock_out:
    spin_unlock_irq(&desc->lock);
 out:
    if ( newaction != NULL )
    {
        free_cpumask_var(newaction->cpu_eoi_map);
        xfree(newaction);
    }
    return rc;
}
