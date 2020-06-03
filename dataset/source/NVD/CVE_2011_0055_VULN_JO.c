static JSBool
CVE_2011_0055_VULN_JO(JSContext *cx, jsval *vp, StringifyContext *scx)
{
    JSObject *obj = JSVAL_TO_OBJECT(*vp);

    if (!scx->cb.append('{'))
        return JS_FALSE;

    jsval vec[3] = {JSVAL_NULL, JSVAL_NULL, JSVAL_NULL};
    JSAutoTempValueRooter tvr(cx, 3, vec);
    jsval& key = vec[0];
    jsval& outputValue = vec[1];

    JSObject *iterObj = NULL;
    jsval *keySource = vp;
    bool usingWhitelist = false;

    // if the replacer is an array, we use the keys from it
    if (scx->replacer && JS_IsArrayObject(cx, scx->replacer)) {
        usingWhitelist = true;
        vec[2] = OBJECT_TO_JSVAL(scx->replacer);
        keySource = &vec[2];
    }

    if (!js_ValueToIterator(cx, JSITER_ENUMERATE, keySource))
        return JS_FALSE;
    iterObj = JSVAL_TO_OBJECT(*keySource);

    JSBool memberWritten = JS_FALSE;

    bool ok = false;
    while (true) {
        outputValue = JSVAL_VOID;
        if (!js_CallIteratorNext(cx, iterObj, &key))
            goto error_break;
        if (key == JSVAL_HOLE)
            break;

        jsuint index = 0;
        if (usingWhitelist) {
            // skip non-index properties
            if (!js_IdIsIndex(key, &index))
                continue;

            jsval newKey;
            if (!scx->replacer->getProperty(cx, key, &newKey))
                goto error_break;
            key = newKey;
        }

        JSString *ks;
        if (JSVAL_IS_STRING(key)) {
            ks = JSVAL_TO_STRING(key);
        } else {
            ks = js_ValueToString(cx, key);
            if (!ks)
                goto error_break;
        }
        JSAutoTempValueRooter keyStringRoot(cx, ks);

        // Don't include prototype properties, since this operation is
        // supposed to be implemented as if by ES3.1 Object.keys()
        jsid id;
        jsval v = JS_FALSE;
        if (!js_ValueToStringId(cx, STRING_TO_JSVAL(ks), &id) ||
            !js_HasOwnProperty(cx, obj->map->ops->lookupProperty, obj, id, &v)) {
            goto error_break;
        }

        if (v != JSVAL_TRUE)
            continue;

        if (!JS_GetPropertyById(cx, obj, id, &outputValue))
            goto error_break;

        if (JSVAL_IS_OBJECT(outputValue) && !js_TryJSON(cx, &outputValue))
            goto error_break;

        // call this here, so we don't write out keys if the replacer function
        // wants to elide the value.
        if (!CallReplacerFunction(cx, id, obj, scx, &outputValue))
            goto error_break;

        JSType type = JS_TypeOfValue(cx, outputValue);

        // elide undefined values and functions and XML
        if (outputValue == JSVAL_VOID || type == JSTYPE_FUNCTION || type == JSTYPE_XML)
            continue;

        // output a comma unless this is the first member to write
        if (memberWritten && !scx->cb.append(','))
            goto error_break;
        memberWritten = JS_TRUE;

        if (!WriteIndent(cx, scx, scx->depth))
            goto error_break;

        // Be careful below, this string is weakly rooted
        JSString *s = js_ValueToString(cx, key);
        if (!s)
            goto error_break;

        const jschar *chars;
        size_t length;
        s->getCharsAndLength(chars, length);
        if (!write_string(cx, scx->cb, chars, length) ||
            !scx->cb.append(':') ||
            !Str(cx, id, obj, scx, &outputValue, false)) {
            goto error_break;
        }
    }
    ok = true;

  error_break:
    if (iterObj) {
        // Always close the iterator, but make sure not to stomp on OK
        JS_ASSERT(OBJECT_TO_JSVAL(iterObj) == *keySource);
        ok &= js_CloseIterator(cx, *keySource);
    }

    if (!ok)
        return JS_FALSE;

    if (memberWritten && !WriteIndent(cx, scx, scx->depth - 1))
        return JS_FALSE;

    return scx->cb.append('}');
}
