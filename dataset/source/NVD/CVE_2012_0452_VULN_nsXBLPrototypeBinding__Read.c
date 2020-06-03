nsresult
CVE_2012_0452_VULN_nsXBLPrototypeBinding::Read(nsIObjectInputStream* aStream,
                            nsXBLDocumentInfo* aDocInfo,
                            nsIDocument* aDocument,
                            PRUint8 aFlags)
{
  mInheritStyle = (aFlags & XBLBinding_Serialize_InheritStyle) ? true : false;

  // nsXBLContentSink::ConstructBinding doesn't create a binding with an empty
  // id, so we don't here either.
  nsCAutoString id;
  nsresult rv = aStream->ReadCString(id);

  NS_ENSURE_SUCCESS(rv, rv);
  NS_ENSURE_TRUE(!id.IsEmpty(), NS_ERROR_FAILURE);

  nsCAutoString baseBindingURI;
  rv = aStream->ReadCString(baseBindingURI);
  NS_ENSURE_SUCCESS(rv, rv);
  mCheckedBaseProto = true;

  if (!baseBindingURI.IsEmpty()) {
    rv = NS_NewURI(getter_AddRefs(mBaseBindingURI), baseBindingURI);
    NS_ENSURE_SUCCESS(rv, rv);
  }

  rv = ReadNamespace(aStream, mBaseNameSpaceID);
  NS_ENSURE_SUCCESS(rv, rv);

  nsAutoString baseTag;
  rv = aStream->ReadString(baseTag);
  NS_ENSURE_SUCCESS(rv, rv);
  if (!baseTag.IsEmpty()) {
    mBaseTag = do_GetAtom(baseTag);
  }

  aDocument->CreateElem(NS_LITERAL_STRING("binding"), nsnull, kNameSpaceID_XBL,
                        getter_AddRefs(mBinding));

  nsCOMPtr<nsIContent> child;
  rv = ReadContentNode(aStream, aDocument, aDocument->NodeInfoManager(), getter_AddRefs(child));
  NS_ENSURE_SUCCESS(rv, rv);

  Element* rootElement = aDocument->GetRootElement();
  if (rootElement)
    rootElement->AppendChildTo(mBinding, false);

  if (child) {
    mBinding->AppendChildTo(child, false);
  }

  PRUint32 interfaceCount;
  rv = aStream->Read32(&interfaceCount);
  NS_ENSURE_SUCCESS(rv, rv);

  if (interfaceCount > 0) {
    NS_ASSERTION(!mInterfaceTable, "non-null mInterfaceTable");
    mInterfaceTable = new nsSupportsHashtable(interfaceCount);
    NS_ENSURE_TRUE(mInterfaceTable, NS_ERROR_OUT_OF_MEMORY);

    for (; interfaceCount > 0; interfaceCount--) {
      nsIID iid;
      aStream->ReadID(&iid);
      nsIIDKey key(iid);
      mInterfaceTable->Put(&key, mBinding);
    }
  }

  nsCOMPtr<nsIScriptGlobalObjectOwner> globalOwner(do_QueryObject(aDocInfo));
  nsIScriptGlobalObject* globalObject = globalOwner->GetScriptGlobalObject();
  NS_ENSURE_TRUE(globalObject, NS_ERROR_UNEXPECTED);

  nsIScriptContext *context = globalObject->GetContext();
  NS_ENSURE_TRUE(context, NS_ERROR_FAILURE);

  bool isFirstBinding = aFlags & XBLBinding_Serialize_IsFirstBinding;
  rv = Init(id, aDocInfo, nsnull, isFirstBinding);
  NS_ENSURE_SUCCESS(rv, rv);

  // We need to set the prototype binding before reading the nsXBLProtoImpl,
  // as it may be retrieved within.
  rv = aDocInfo->SetPrototypeBinding(id, this);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCAutoString className;
  rv = aStream->ReadCString(className);
  NS_ENSURE_SUCCESS(rv, rv);

  if (!className.IsEmpty()) {
    nsXBLProtoImpl* impl; // NS_NewXBLProtoImpl will set mImplementation for us
    NS_NewXBLProtoImpl(this, NS_ConvertUTF8toUTF16(className).get(), &impl);

    // This needs to happen after SetPrototypeBinding as calls are made to
    // retrieve the mapped bindings from within here. However, if an error
    // occurs, the mapping should be removed again so that we don't keep an
    // invalid binding around.
    rv = mImplementation->Read(context, aStream, this, globalObject);
    if (NS_FAILED(rv)) {
      aDocInfo->RemovePrototypeBinding(id);
      return rv;
    }
  }

  // Next read in the handlers.
  nsXBLPrototypeHandler* previousHandler = nsnull;

  do {
    XBLBindingSerializeDetails type;
    rv = aStream->Read8(&type);
    NS_ENSURE_SUCCESS(rv, rv);

    if (type == XBLBinding_Serialize_NoMoreItems)
      break;

    NS_ASSERTION((type & XBLBinding_Serialize_Mask) == XBLBinding_Serialize_Handler,
                 "invalid handler type");

    nsXBLPrototypeHandler* handler = new nsXBLPrototypeHandler(this);
    rv = handler->Read(context, aStream);
    if (NS_FAILED(rv)) {
      delete handler;
      return rv;
    }

    if (previousHandler) {
      previousHandler->SetNextHandler(handler);
    }
    else {
      SetPrototypeHandlers(handler);
    }
    previousHandler = handler;
  } while (1);

  // Finally, read in the resources.
  do {
    XBLBindingSerializeDetails type;
    rv = aStream->Read8(&type);
    NS_ENSURE_SUCCESS(rv, rv);

    if (type == XBLBinding_Serialize_NoMoreItems)
      break;

    NS_ASSERTION((type & XBLBinding_Serialize_Mask) == XBLBinding_Serialize_Stylesheet ||
                 (type & XBLBinding_Serialize_Mask) == XBLBinding_Serialize_Image, "invalid resource type");

    nsAutoString src;
    rv = aStream->ReadString(src);
    NS_ENSURE_SUCCESS(rv, rv);

    AddResource(type == XBLBinding_Serialize_Stylesheet ? nsGkAtoms::stylesheet :
                                                          nsGkAtoms::image, src);
  } while (1);

  if (isFirstBinding) {
    aDocInfo->SetFirstPrototypeBinding(this);
  }

  return NS_OK;
}
