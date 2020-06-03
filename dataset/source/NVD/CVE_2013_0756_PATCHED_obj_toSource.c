static JSBool
CVE_2013_0756_PATCHED_obj_toSource(JSContext *cx, unsigned argc, Value *vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);
    JS_CHECK_RECURSION(cx, return JS_FALSE);

    RootedObject obj(cx, ToObject(cx, args.thisv()));
    if (!obj)
        return false;

    /* If outermost, we need parentheses to be an expression, not a block. */
    bool outermost = (cx->cycleDetectorSet.count() == 0);

    AutoCycleDetector detector(cx, obj);
    if (!detector.init())
        return false;
    if (detector.foundCycle()) {
        JSString *str = js_NewStringCopyZ(cx, "{}");
        if (!str)
            return false;
        args.rval().setString(str);
        return true;
    }

    StringBuffer buf(cx);
    if (outermost && !buf.append('('))
        return false;
    if (!buf.append('{'))
        return false;

    Value val[2];
    PodArrayZero(val);
    AutoArrayRooter tvr2(cx, ArrayLength(val), val);

    JSString *gsop[2];
    SkipRoot skipGsop(cx, &gsop, 2);

    AutoIdVector idv(cx);
    if (!GetPropertyNames(cx, obj, JSITER_OWNONLY, &idv))
        return false;

    bool comma = false;
    for (size_t i = 0; i < idv.length(); ++i) {
        RootedId id(cx, idv[i]);
        RootedObject obj2(cx);
        RootedShape shape(cx);
        if (!JSObject::lookupGeneric(cx, obj, id, &obj2, &shape))
            return false;

        /*  Decide early whether we prefer get/set or old getter/setter syntax. */
        int valcnt = 0;
        if (shape) {
            bool doGet = true;
            if (obj2->isNative()) {
                unsigned attrs = shape->attributes();
                if (attrs & JSPROP_GETTER) {
                    doGet = false;
                    val[valcnt] = shape->getterValue();
                    gsop[valcnt] = cx->runtime->atomState.getAtom;
                    valcnt++;
                }
                if (attrs & JSPROP_SETTER) {
                    doGet = false;
                    val[valcnt] = shape->setterValue();
                    gsop[valcnt] = cx->runtime->atomState.setAtom;
                    valcnt++;
                }
            }
            if (doGet) {
                valcnt = 1;
                gsop[0] = NULL;
                MutableHandleValue vp = MutableHandleValue::fromMarkedLocation(&val[0]);
                if (!JSObject::getGeneric(cx, obj, obj, id, vp))
                    return false;
            }
        }

        /* Convert id to a linear string. */
        RawString s = ToString(cx, IdToValue(id));
        if (!s)
            return false;
        Rooted<JSLinearString*> idstr(cx, s->ensureLinear(cx));
        if (!idstr)
            return false;

        /*
         * If id is a string that's not an identifier, or if it's a negative
         * integer, then it must be quoted.
         */
        if (JSID_IS_ATOM(id)
            ? !IsIdentifier(idstr)
            : (!JSID_IS_INT(id) || JSID_TO_INT(id) < 0))
        {
            s = js_QuoteString(cx, idstr, jschar('\''));
            if (!s || !(idstr = s->ensureLinear(cx)))
                return false;
        }

        for (int j = 0; j < valcnt; j++) {
            /*
             * Censor an accessor descriptor getter or setter part if it's
             * undefined.
             */
            if (gsop[j] && val[j].isUndefined())
                continue;

            /* Convert val[j] to its canonical source form. */
            RootedString valstr(cx, js_ValueToSource(cx, val[j]));
            if (!valstr)
                return false;
            const jschar *vchars = valstr->getChars(cx);
            if (!vchars)
                return false;
            size_t vlength = valstr->length();

            /*
             * Remove '(function ' from the beginning of valstr and ')' from the
             * end so that we can put "get" in front of the function definition.
             */
            if (gsop[j] && IsFunctionObject(val[j])) {
                const jschar *start = vchars;
                const jschar *end = vchars + vlength;

                uint8_t parenChomp = 0;
                if (vchars[0] == '(') {
                    vchars++;
                    parenChomp = 1;
                }

                /* Try to jump "function" keyword. */
                if (vchars)
                    vchars = js_strchr_limit(vchars, ' ', end);

                /*
                 * Jump over the function's name: it can't be encoded as part
                 * of an ECMA getter or setter.
                 */
                if (vchars)
                    vchars = js_strchr_limit(vchars, '(', end);

                if (vchars) {
                    if (*vchars == ' ')
                        vchars++;
                    vlength = end - vchars - parenChomp;
                } else {
                    gsop[j] = NULL;
                    vchars = start;
                }
            }

            if (comma && !buf.append(", "))
                return false;
            comma = true;

            if (gsop[j])
                if (!buf.append(gsop[j]) || !buf.append(' '))
                    return false;

            if (!buf.append(idstr))
                return false;
            if (!buf.append(gsop[j] ? ' ' : ':'))
                return false;

            if (!buf.append(vchars, vlength))
                return false;
        }
    }

    if (!buf.append('}'))
        return false;
    if (outermost && !buf.append(')'))
        return false;

    RawString str = buf.finishString();
    if (!str)
        return false;
    args.rval().setString(str);
    return true;
}
