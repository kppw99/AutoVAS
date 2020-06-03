nsresult
CVE_2012_1967_VULN_xpc_EvalInSandbox(JSContext *cx, JSObject *sandbox, const nsAString& source,
                  const char *filename, PRInt32 lineNo,
                  JSVersion jsVersion, bool returnStringOnly, jsval *rval)
{
    JS_AbortIfWrongThread(JS_GetRuntime(cx));

#ifdef DEBUG
    // NB: The "unsafe" unwrap here is OK because we must be called from chrome.
    {
        nsIScriptSecurityManager *ssm = XPCWrapper::GetSecurityManager();
        if (ssm) {
            JSStackFrame *fp;
            nsIPrincipal *subjectPrincipal =
                ssm->GetCxSubjectPrincipalAndFrame(cx, &fp);
            bool system;
            ssm->IsSystemPrincipal(subjectPrincipal, &system);
            if (fp && !system) {
                ssm->IsCapabilityEnabled("UniversalXPConnect", &system);
                NS_ASSERTION(system, "Bad caller!");
            }
        }
    }
#endif

    sandbox = XPCWrapper::UnsafeUnwrapSecurityWrapper(sandbox);
    if (!sandbox || js::GetObjectJSClass(sandbox) != &SandboxClass) {
        return NS_ERROR_INVALID_ARG;
    }

    nsIScriptObjectPrincipal *sop =
        (nsIScriptObjectPrincipal*)xpc_GetJSPrivate(sandbox);
    NS_ASSERTION(sop, "Invalid sandbox passed");
    nsCOMPtr<nsIPrincipal> prin = sop->GetPrincipal();

    if (!prin) {
        return NS_ERROR_FAILURE;
    }

    nsCAutoString filenameBuf;
    if (!filename) {
        // Default to the spec of the principal.
        nsJSPrincipals::get(prin)->GetScriptLocation(filenameBuf);
        filename = filenameBuf.get();
        lineNo = 1;
    }

    JSObject *callingScope;
    {
        JSAutoRequest req(cx);

        callingScope = JS_GetGlobalForScopeChain(cx);
        if (!callingScope) {
            return NS_ERROR_FAILURE;
        }
    }

    nsRefPtr<ContextHolder> sandcx = new ContextHolder(cx, sandbox);
    if (!sandcx || !sandcx->GetJSContext()) {
        JS_ReportError(cx, "Can't prepare context for evalInSandbox");
        return NS_ERROR_OUT_OF_MEMORY;
    }

    if (jsVersion != JSVERSION_DEFAULT)
        JS_SetVersion(sandcx->GetJSContext(), jsVersion);

    XPCPerThreadData *data = XPCPerThreadData::GetData(cx);
    XPCJSContextStack *stack = nsnull;
    if (data && (stack = data->GetJSContextStack())) {
        if (!stack->Push(sandcx->GetJSContext())) {
            JS_ReportError(cx,
                           "Unable to initialize XPConnect with the sandbox context");
            return NS_ERROR_FAILURE;
        }
    }

    nsresult rv = NS_OK;

    {
        JSAutoRequest req(sandcx->GetJSContext());
        JSAutoEnterCompartment ac;

        if (!ac.enter(sandcx->GetJSContext(), sandbox)) {
            if (stack)
                unused << stack->Pop();
            return NS_ERROR_FAILURE;
        }

        jsval v;
        JSString *str = nsnull;
        JSBool ok =
            JS_EvaluateUCScriptForPrincipals(sandcx->GetJSContext(), sandbox,
                                             nsJSPrincipals::get(prin),
                                             reinterpret_cast<const jschar *>
                                                             (PromiseFlatString(source).get()),
                                             source.Length(), filename, lineNo,
                                             &v);
        if (ok && returnStringOnly && !(JSVAL_IS_VOID(v))) {
            ok = !!(str = JS_ValueToString(sandcx->GetJSContext(), v));
        }

        if (!ok) {
            // The sandbox threw an exception, convert it to a string (if
            // asked) or convert it to a SJOW.

            jsval exn;
            if (JS_GetPendingException(sandcx->GetJSContext(), &exn)) {
                JS_ClearPendingException(sandcx->GetJSContext());

                if (returnStringOnly) {
                    // The caller asked for strings only, convert the
                    // exception into a string.
                    str = JS_ValueToString(sandcx->GetJSContext(), exn);

                    if (str) {
                        // We converted the exception to a string. Use that
                        // as the value exception.
                        exn = STRING_TO_JSVAL(str);
                        if (JS_WrapValue(cx, &exn)) {
                            JS_SetPendingException(cx, exn);
                        } else {
                            JS_ClearPendingException(cx);
                            rv = NS_ERROR_FAILURE;
                        }
                    } else {
                        JS_ClearPendingException(cx);
                        rv = NS_ERROR_FAILURE;
                    }
                } else {
                    if (JS_WrapValue(cx, &exn)) {
                        JS_SetPendingException(cx, exn);
                    }
                }


                // Clear str so we don't confuse callers.
                str = nsnull;
            } else {
                rv = NS_ERROR_OUT_OF_MEMORY;
            }
        } else {
            // Convert the result into something safe for our caller.
            JSAutoRequest req(cx);
            JSAutoEnterCompartment ac;
            if (str) {
                v = STRING_TO_JSVAL(str);
            }

            xpc::CompartmentPrivate *sandboxdata =
                static_cast<xpc::CompartmentPrivate *>
                           (JS_GetCompartmentPrivate(js::GetObjectCompartment(sandbox)));
            if (!ac.enter(cx, callingScope) ||
                !WrapForSandbox(cx, sandboxdata->wantXrays, &v)) {
                rv = NS_ERROR_FAILURE;
            }

            if (NS_SUCCEEDED(rv)) {
                *rval = v;
            }
        }
    }

    if (stack)
        unused << stack->Pop();

    return rv;
}
