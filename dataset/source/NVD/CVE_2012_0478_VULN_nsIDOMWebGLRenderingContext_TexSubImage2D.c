static JSBool
CVE_2012_0478_VULN_nsIDOMWebGLRenderingContext_TexSubImage2D(JSContext *cx, uintN argc, jsval *vp)
{
    XPC_QS_ASSERT_CONTEXT_OK(cx);
    JSObject *obj = JS_THIS_OBJECT(cx, vp);
    if (!obj)
        return JS_FALSE;

    nsresult rv;

    nsIDOMWebGLRenderingContext *self;
    xpc_qsSelfRef selfref;
    js::AutoValueRooter tvr(cx);
    if (!xpc_qsUnwrapThis(cx, obj, nsnull, &self, &selfref.ptr, tvr.jsval_addr(), nsnull))
        return JS_FALSE;

    if (argc < 7 || argc == 8)
        return xpc_qsThrow(cx, NS_ERROR_XPC_NOT_ENOUGH_ARGS);

    jsval *argv = JS_ARGV(cx, vp);

    // arguments common to all cases
    GET_UINT32_ARG(argv0, 0);
    GET_INT32_ARG(argv1, 1);
    GET_INT32_ARG(argv2, 2);
    GET_INT32_ARG(argv3, 3);

    if (argc > 6 &&
        !JSVAL_IS_PRIMITIVE(argv[6]))
    {
        // implement the variants taking a DOMElement as argv[6]
        GET_UINT32_ARG(argv4, 4);
        GET_UINT32_ARG(argv5, 5);

        nsIDOMElement *elt;
        xpc_qsSelfRef eltRef;
        rv = xpc_qsUnwrapArg<nsIDOMElement>(cx, argv[6], &elt, &eltRef.ptr, &argv[6]);
        if (NS_FAILED(rv)) return JS_FALSE;

        rv = self->TexSubImage2D_dom(argv0, argv1, argv2, argv3, argv4, argv5, elt);
        
        // NS_ERROR_DOM_SECURITY_ERR indicates we tried to load a cross-domain element, so
        // bail out immediately, don't try to interprete as ImageData
        if (rv == NS_ERROR_DOM_SECURITY_ERR) {
            xpc_qsThrowBadArg(cx, rv, vp, 6);
            return JS_FALSE;
        }

        if (NS_FAILED(rv)) {
            // failed to interprete argv[6] as a DOMElement, now try to interprete it as ImageData
            JSObject *argv6 = JSVAL_TO_OBJECT(argv[6]);
            jsval js_width, js_height, js_data;
            JS_GetProperty(cx, argv6, "width", &js_width);
            JS_GetProperty(cx, argv6, "height", &js_height);
            JS_GetProperty(cx, argv6, "data", &js_data);
            if (js_width  == JSVAL_VOID ||
                js_height == JSVAL_VOID ||
                js_data   == JSVAL_VOID)
            {
                xpc_qsThrowBadArg(cx, NS_ERROR_FAILURE, vp, 6);
                return JS_FALSE;
            }
            int32_t int_width, int_height;
            JSObject *obj_data = JSVAL_TO_OBJECT(js_data);
            if (!JS_ValueToECMAInt32(cx, js_width, &int_width) ||
                !JS_ValueToECMAInt32(cx, js_height, &int_height))
            {
                return JS_FALSE;
            }
            if (!js_IsTypedArray(obj_data))
            {
                xpc_qsThrowBadArg(cx, NS_ERROR_FAILURE, vp, 6);
                return JS_FALSE;
            }
            rv = self->TexSubImage2D_imageData(argv0, argv1, argv2, argv3,
                                               int_width, int_height,
                                               argv4, argv5,
                                               js::TypedArray::getTypedArray(obj_data));
        }
    } else if (argc > 8 &&
               !JSVAL_IS_PRIMITIVE(argv[8]))
    {
        // implement the variants taking a buffer/array as argv[8]
        GET_INT32_ARG(argv4, 4);
        GET_INT32_ARG(argv5, 5);
        GET_UINT32_ARG(argv6, 6);
        GET_UINT32_ARG(argv7, 7);

        JSObject *argv8 = JSVAL_TO_OBJECT(argv[8]);
        // try to grab a js::TypedArray
        if (js_IsTypedArray(argv8)) {
            rv = self->TexSubImage2D_array(argv0, argv1, argv2, argv3,
                                           argv4, argv5, argv6, argv7,
                                           js::TypedArray::getTypedArray(argv8));
        } else {
            xpc_qsThrowBadArg(cx, NS_ERROR_FAILURE, vp, 8);
            return JS_FALSE;
        }
    } else {
        xpc_qsThrow(cx, NS_ERROR_XPC_NOT_ENOUGH_ARGS);
        return JS_FALSE;
    }

    if (NS_FAILED(rv))
        return xpc_qsThrowMethodFailed(cx, rv, vp);

    *vp = JSVAL_VOID;
    return JS_TRUE;
}
