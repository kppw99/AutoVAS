    PRBool CVE_2011_3003_VULN_CopyDataIfElementArray(const void* data) {
        if (mTarget == LOCAL_GL_ELEMENT_ARRAY_BUFFER) {
            mData = realloc(mData, mByteLength);
            if (!mData)
                return PR_FALSE;
            memcpy(mData, data, mByteLength);
        }
        return PR_TRUE;
    }
