bool
CVE_2013_0756_VULN_js_EnterSharpObject(JSContext *cx, HandleObject obj, JSIdArray **idap, bool *alreadySeen, bool *isSharp)
{
    if (!JS_CHECK_OPERATION_LIMIT(cx))
        return false;

    *alreadySeen = false;

    JSSharpObjectMap *map = &cx->sharpObjectMap;

    JS_ASSERT_IF(map->depth == 0, map->table.count() == 0);
    JS_ASSERT_IF(map->table.count() == 0, map->depth == 0);

    JSSharpTable::Ptr p;
    JSSharpInfo sharpid;
    JSIdArray *ida = NULL;

    /* From this point the control must flow either through out: or bad:. */
    if (map->depth == 0) {
        JS_KEEP_ATOMS(cx->runtime);

        /*
         * Although MarkSharpObjects tries to avoid invoking getters,
         * it ends up doing so anyway under some circumstances; for
         * example, if a wrapped object has getters, the wrapper will
         * prevent MarkSharpObjects from recognizing them as such.
         * This could lead to js_LeaveSharpObject being called while
         * MarkSharpObjects is still working.
         *
         * Increment map->depth while we call MarkSharpObjects, to
         * ensure that such a call doesn't free the hash table we're
         * still using.
         */
        map->depth = 1;
        bool success = MarkSharpObjects(cx, obj, &ida, &sharpid);
        JS_ASSERT(map->depth == 1);
        map->depth = 0;
        if (!success)
            goto bad;
        JS_ASSERT(!sharpid.isSharp);
        if (!idap) {
            JS_DestroyIdArray(cx, ida);
            ida = NULL;
        }
    } else {
        /*
         * It's possible that the value of a property has changed from the
         * first time the object's properties are traversed (when the property
         * ids are entered into the hash table) to the second (when they are
         * converted to strings), i.e., the JSObject::getProperty() call is not
         * idempotent.
         */
        p = map->table.lookup(obj);
        if (!p) {
            if (!map->table.put(obj.get(), sharpid))
                goto bad;
            goto out;
        }
        sharpid = p->value;
    }

    if (sharpid.isSharp || sharpid.hasGen)
        *alreadySeen = true;

out:
    if (!sharpid.isSharp) {
        if (idap && !ida) {
            ida = JS_Enumerate(cx, obj);
            if (!ida)
                goto bad;
        }
        map->depth++;
    }

    if (idap)
        *idap = ida;
    *isSharp = sharpid.isSharp;
    return true;

bad:
    /* Clean up the sharpObjectMap table on outermost error. */
    if (map->depth == 0) {
        JS_UNKEEP_ATOMS(cx->runtime);
        map->sharpgen = 0;
        map->table.clear();
    }
    return false;
}
