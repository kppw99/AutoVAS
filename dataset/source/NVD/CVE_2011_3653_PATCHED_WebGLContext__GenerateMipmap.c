NS_IMETHODIMP
CVE_2011_3653_PATCHED_WebGLContext::GenerateMipmap(WebGLenum target)
{
    if (!ValidateTextureTargetEnum(target, "generateMipmap"))
        return NS_OK;

    WebGLTexture *tex = activeBoundTextureForTarget(target);

    if (!tex)
        return ErrorInvalidOperation("generateMipmap: no texture is bound to this target");

    if (!tex->IsFirstImagePowerOfTwo()) {
        return ErrorInvalidOperation("generateMipmap: the width or height of this texture is not a power of two");
    }

    if (!tex->AreAllLevel0ImageInfosEqual()) {
        return ErrorInvalidOperation("generateMipmap: the six faces of this cube map have different dimensions, format, or type.");
    }

    tex->SetGeneratedMipmap();

    MakeContextCurrent();

#ifdef XP_MACOSX
    // On Mac, glGenerateMipmap on a texture whose minification filter does NOT require a mipmap at the time of the call,
    // will happily grab random video memory into certain mipmap levels. See bug 684882.
    // Thanks to Kenneth Russell / Google for figuring this out.
    // So we temporarily spoof the minification filter, call glGenerateMipmap,
    // and restore it. If that turned out to not be enough, we would have to avoid calling glGenerateMipmap altogether and
    // emulate it.
    if (tex->DoesMinFilterRequireMipmap()) {
        gl->fGenerateMipmap(target);
    } else {
        // spoof the min filter as something that requires a mipmap. The particular choice of a filter doesn't matter as
        // we're not rendering anything here. Since LINEAR_MIPMAP_LINEAR is by far the most common use case, and we're trying
        // to work around a bug triggered by "unexpected" min filters, it seems to be the safest choice.
        gl->fTexParameteri(target, LOCAL_GL_TEXTURE_MIN_FILTER, LOCAL_GL_LINEAR_MIPMAP_LINEAR);
        gl->fGenerateMipmap(target);
        gl->fTexParameteri(target, LOCAL_GL_TEXTURE_MIN_FILTER, tex->MinFilter());
    }
#else
    gl->fGenerateMipmap(target);
#endif
    
    return NS_OK;
}
