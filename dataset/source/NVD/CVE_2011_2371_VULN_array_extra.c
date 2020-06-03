static JSBool
CVE_2011_2371_VULN_array_extra(JSContext *cx, ArrayExtraMode mode, uintN argc, Value *vp)
{
    JSObject *obj = ToObject(cx, &vp[1]);
    if (!obj)
        return false;

    jsuint length;
    if (!js_GetLengthProperty(cx, obj, &length))
        return JS_FALSE;

    /*
     * First, get or compute our callee, so that we error out consistently
     * when passed a non-callable object.
     */
    if (argc == 0) {
        js_ReportMissingArg(cx, *vp, 0);
        return JS_FALSE;
    }
    Value *argv = vp + 2;
    JSObject *callable = js_ValueToCallableObject(cx, &argv[0], JSV2F_SEARCH_STACK);
    if (!callable)
        return JS_FALSE;

    /*
     * Set our initial return condition, used for zero-length array cases
     * (and pre-size our map return to match our known length, for all cases).
     */
    jsuint newlen;
    JSObject *newarr;
#ifdef __GNUC__ /* quell GCC overwarning */
    newlen = 0;
    newarr = NULL;
#endif
    jsint start = 0, end = length, step = 1;

    switch (mode) {
      case REDUCE_RIGHT:
        start = length - 1, end = -1, step = -1;
        /* FALL THROUGH */
      case REDUCE:
        if (length == 0 && argc == 1) {
            JS_ReportErrorNumber(cx, js_GetErrorMessage, NULL,
                                 JSMSG_EMPTY_ARRAY_REDUCE);
            return JS_FALSE;
        }
        if (argc >= 2) {
            *vp = argv[1];
        } else {
            JSBool hole;
            do {
                if (!GetElement(cx, obj, start, &hole, vp))
                    return JS_FALSE;
                start += step;
            } while (hole && start != end);

            if (hole && start == end) {
                JS_ReportErrorNumber(cx, js_GetErrorMessage, NULL,
                                     JSMSG_EMPTY_ARRAY_REDUCE);
                return JS_FALSE;
            }
        }
        break;
      case MAP:
      case FILTER:
        newlen = (mode == MAP) ? length : 0;
        newarr = NewDenseAllocatedArray(cx, newlen);
        if (!newarr)
            return JS_FALSE;
        vp->setObject(*newarr);
        break;
      case SOME:
        vp->setBoolean(false);
        break;
      case EVERY:
        vp->setBoolean(true);
        break;
      case FOREACH:
        vp->setUndefined();
        break;
    }

    if (length == 0)
        return JS_TRUE;

    Value thisv = (argc > 1 && !REDUCE_MODE(mode)) ? argv[1] : UndefinedValue();

    /*
     * For all but REDUCE, we call with 3 args (value, index, array). REDUCE
     * requires 4 args (accum, value, index, array).
     */
    argc = 3 + REDUCE_MODE(mode);

    InvokeSessionGuard session;
    if (!session.start(cx, ObjectValue(*callable), thisv, argc))
        return JS_FALSE;

    MUST_FLOW_THROUGH("out");
    JSBool ok = JS_TRUE;
    JSBool cond;

    Value objv = ObjectValue(*obj);
    AutoValueRooter tvr(cx);
    for (jsint i = start; i != end; i += step) {
        JSBool hole;
        ok = JS_CHECK_OPERATION_LIMIT(cx) &&
             GetElement(cx, obj, i, &hole, tvr.addr());
        if (!ok)
            goto out;
        if (hole)
            continue;

        /*
         * Push callable and 'this', then args. We must do this for every
         * iteration around the loop since Invoke clobbers its arguments.
         */
        uintN argi = 0;
        if (REDUCE_MODE(mode))
            session[argi++] = *vp;
        session[argi++] = tvr.value();
        session[argi++] = Int32Value(i);
        session[argi]   = objv;

        /* Do the call. */
        ok = session.invoke(cx);
        if (!ok)
            break;

        const Value &rval = session.rval();

        if (mode > MAP)
            cond = js_ValueToBoolean(rval);
#ifdef __GNUC__ /* quell GCC overwarning */
        else
            cond = JS_FALSE;
#endif

        switch (mode) {
          case FOREACH:
            break;
          case REDUCE:
          case REDUCE_RIGHT:
            *vp = rval;
            break;
          case MAP:
            ok = SetArrayElement(cx, newarr, i, rval);
            if (!ok)
                goto out;
            break;
          case FILTER:
            if (!cond)
                break;
            /* The element passed the filter, so push it onto our result. */
            ok = SetArrayElement(cx, newarr, newlen++, tvr.value());
            if (!ok)
                goto out;
            break;
          case SOME:
            if (cond) {
                vp->setBoolean(true);
                goto out;
            }
            break;
          case EVERY:
            if (!cond) {
                vp->setBoolean(false);
                goto out;
            }
            break;
        }
    }

  out:
    if (ok && mode == FILTER)
        ok = js_SetLengthProperty(cx, newarr, newlen);
    return ok;
}
