nsresult
CVE_2013_5601_VULN_nsEventListenerManager::CompileEventHandlerInternal(nsListenerStruct *aListenerStruct,
                                                    bool aNeedsCxPush,
                                                    const nsAString* aBody)
{
  NS_PRECONDITION(aListenerStruct->GetJSListener(),
                  "Why do we not have a JS listener?");
  NS_PRECONDITION(aListenerStruct->mHandlerIsString,
                  "Why are we compiling a non-string JS listener?");

  nsresult result = NS_OK;

  nsIJSEventListener *listener = aListenerStruct->GetJSListener();
  NS_ASSERTION(!listener->GetHandler().HasEventHandler(),
               "What is there to compile?");

  nsIScriptContext *context = listener->GetEventContext();
  JSContext *cx = context->GetNativeContext();
  JS::Rooted<JSObject*> handler(cx);

  nsCOMPtr<nsPIDOMWindow> win; // Will end up non-null if mTarget is a window

  nsCxPusher pusher;
  if (aNeedsCxPush) {
    pusher.Push(cx);
  }

  if (aListenerStruct->mHandlerIsString) {
    // OK, we didn't find an existing compiled event handler.  Flag us
    // as not a string so we don't keep trying to compile strings
    // which can't be compiled
    aListenerStruct->mHandlerIsString = false;

    // mTarget may not be an nsIContent if it's a window and we're
    // getting an inline event listener forwarded from <html:body> or
    // <html:frameset> or <xul:window> or the like.
    // XXX I don't like that we have to reference content from
    // here. The alternative is to store the event handler string on
    // the nsIJSEventListener itself, and that still doesn't address
    // the arg names issue.
    nsCOMPtr<nsIContent> content = do_QueryInterface(mTarget);
    nsAutoString handlerBody;
    const nsAString* body = aBody;
    if (content && !aBody) {
      nsIAtom* attrName = aListenerStruct->mTypeAtom;
      if (aListenerStruct->mTypeAtom == nsGkAtoms::onSVGLoad)
        attrName = nsGkAtoms::onload;
      else if (aListenerStruct->mTypeAtom == nsGkAtoms::onSVGUnload)
        attrName = nsGkAtoms::onunload;
      else if (aListenerStruct->mTypeAtom == nsGkAtoms::onSVGAbort)
        attrName = nsGkAtoms::onabort;
      else if (aListenerStruct->mTypeAtom == nsGkAtoms::onSVGError)
        attrName = nsGkAtoms::onerror;
      else if (aListenerStruct->mTypeAtom == nsGkAtoms::onSVGResize)
        attrName = nsGkAtoms::onresize;
      else if (aListenerStruct->mTypeAtom == nsGkAtoms::onSVGScroll)
        attrName = nsGkAtoms::onscroll;
      else if (aListenerStruct->mTypeAtom == nsGkAtoms::onSVGZoom)
        attrName = nsGkAtoms::onzoom;
      else if (aListenerStruct->mTypeAtom == nsGkAtoms::onbeginEvent)
        attrName = nsGkAtoms::onbegin;
      else if (aListenerStruct->mTypeAtom == nsGkAtoms::onrepeatEvent)
        attrName = nsGkAtoms::onrepeat;
      else if (aListenerStruct->mTypeAtom == nsGkAtoms::onendEvent)
        attrName = nsGkAtoms::onend;

      content->GetAttr(kNameSpaceID_None, attrName, handlerBody);
      body = &handlerBody;
    }

    uint32_t lineNo = 0;
    nsAutoCString url (NS_LITERAL_CSTRING("-moz-evil:lying-event-listener"));
    nsCOMPtr<nsIDocument> doc;
    if (content) {
      doc = content->OwnerDoc();
    } else {
      win = do_QueryInterface(mTarget);
      if (win) {
        doc = win->GetExtantDoc();
      }
    }

    if (doc) {
      nsIURI *uri = doc->GetDocumentURI();
      if (uri) {
        uri->GetSpec(url);
        lineNo = 1;
      }
    }

    uint32_t argCount;
    const char **argNames;
    // If no content, then just use kNameSpaceID_None for the
    // namespace ID.  In practice, it doesn't matter since SVG is
    // the only thing with weird arg names and SVG doesn't map event
    // listeners to the window.
    nsContentUtils::GetEventArgNames(content ?
                                       content->GetNameSpaceID() :
                                       kNameSpaceID_None,
                                     aListenerStruct->mTypeAtom,
                                     &argCount, &argNames);

    JSAutoCompartment ac(cx, context->GetNativeGlobal());
    JS::CompileOptions options(cx);
    options.setFileAndLine(url.get(), lineNo)
           .setVersion(SCRIPTVERSION_DEFAULT);

    JS::Rooted<JSObject*> handlerFun(cx);
    result = nsJSUtils::CompileFunction(cx, JS::NullPtr(), options,
                                        nsAtomCString(aListenerStruct->mTypeAtom),
                                        argCount, argNames, *body, handlerFun.address());
    NS_ENSURE_SUCCESS(result, result);
    handler = handlerFun;
    NS_ENSURE_TRUE(handler, NS_ERROR_FAILURE);
  }

  if (handler) {
    // Bind it
    JS::Rooted<JSObject*> boundHandler(cx);
    JS::Rooted<JSObject*> scope(cx, listener->GetEventScope());
    context->BindCompiledEventHandler(mTarget, scope, handler, &boundHandler);
    if (listener->EventName() == nsGkAtoms::onerror && win) {
      nsRefPtr<OnErrorEventHandlerNonNull> handlerCallback =
        new OnErrorEventHandlerNonNull(boundHandler);
      listener->SetHandler(handlerCallback);
    } else if (listener->EventName() == nsGkAtoms::onbeforeunload && win) {
      nsRefPtr<BeforeUnloadEventHandlerNonNull> handlerCallback =
        new BeforeUnloadEventHandlerNonNull(boundHandler);
      listener->SetHandler(handlerCallback);
    } else {
      nsRefPtr<EventHandlerNonNull> handlerCallback =
        new EventHandlerNonNull(boundHandler);
      listener->SetHandler(handlerCallback);
    }
  }

  return result;
}
