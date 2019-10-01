    PRBool CVE_2011_3003_VULN_ZeroDataIfElementArray() {
        if (mTarget == LOCAL_GL_ELEMENT_ARRAY_BUFFER) {
            mData = realloc(mData, mByteLength);
            if (!mData)
                return PR_FALSE;
            memset(mData, 0, mByteLength);
        }
        return PR_TRUE;
    }
