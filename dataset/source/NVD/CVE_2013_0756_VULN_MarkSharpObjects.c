static bool
CVE_2013_0756_VULN_MarkSharpObjects(JSContext *cx, HandleObject obj, JSIdArray **idap, JSSharpInfo *value)
{
    JS_CHECK_RECURSION(cx, return false);

    JSIdArray *ida;

    JSSharpObjectMap *map = &cx->sharpObjectMap;
    JS_ASSERT(map->depth >= 1);
    JSSharpInfo sharpid;
    JSSharpTable::Ptr p = map->table.lookup(obj);
    if (!p) {
        if (!map->table.put(obj.get(), sharpid))
            return false;

        ida = JS_Enumerate(cx, obj);
        if (!ida)
            return false;

        bool ok = true;
        RootedId id(cx);
        for (int i = 0, length = ida->length; i < length; i++) {
            id = ida->vector[i];
            RootedObject obj2(cx);
            RootedShape prop(cx);
            ok = JSObject::lookupGeneric(cx, obj, id, &obj2, &prop);
            if (!ok)
                break;
            if (!prop)
                continue;
            bool hasGetter, hasSetter;
            RootedValue value(cx), setter(cx);
            if (obj2->isNative()) {
                Shape *shape = (Shape *) prop;
                hasGetter = shape->hasGetterValue();
                hasSetter = shape->hasSetterValue();
                if (hasGetter)
                    value = shape->getterValue();
                if (hasSetter)
                    setter = shape->setterValue();
            } else {
                hasGetter = hasSetter = false;
            }
            if (hasSetter) {
                /* Mark the getter, then set val to setter. */
                if (hasGetter && value.isObject()) {
                    Rooted<JSObject*> vobj(cx, &value.toObject());
                    ok = CVE_2013_0756_VULN_MarkSharpObjects(cx, vobj, NULL, NULL);
                    if (!ok)
                        break;
                }
                value = setter;
            } else if (!hasGetter) {
                ok = JSObject::getGeneric(cx, obj, obj, id, &value);
                if (!ok)
                    break;
            }
            if (value.isObject()) {
                Rooted<JSObject*> vobj(cx, &value.toObject());
                if (!CVE_2013_0756_VULN_MarkSharpObjects(cx, vobj, NULL, NULL)) {
                    ok = false;
                    break;
                }
            }
        }
        if (!ok || !idap)
            JS_DestroyIdArray(cx, ida);
        if (!ok)
            return false;
    } else {
        if (!p->value.hasGen && !p->value.isSharp) {
            p->value.hasGen = true;
        }
        sharpid = p->value;
        ida = NULL;
    }
    if (idap)
        *idap = ida;
    if (value)
        *value = sharpid;
    return true;
}
