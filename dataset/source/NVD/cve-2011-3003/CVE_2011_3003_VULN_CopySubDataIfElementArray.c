    void CVE_2011_3003_VULN_CopySubDataIfElementArray(GLuint byteOffset, GLuint byteLength, const void* data) {
        if (mTarget == LOCAL_GL_ELEMENT_ARRAY_BUFFER) {
            memcpy((void*) (size_t(mData)+byteOffset), data, byteLength);
        }
    }
