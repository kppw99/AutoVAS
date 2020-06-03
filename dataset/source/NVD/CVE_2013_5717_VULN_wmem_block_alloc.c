static void *
CVE_2013_5717_VULN_wmem_block_alloc(void *private_data, const size_t size)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    wmem_block_chunk_t     *chunk;

    /* We can't allocate more than will fit in a block (less our header),
     * which is an awful lot. */
    g_assert(size < WMEM_BLOCK_SIZE - sizeof(wmem_block_chunk_t));

    if (allocator->free_list_head == NULL) {
        /* No free chunks at all, grab a new block */
        wmem_block_new_block(allocator);
    }
    else if (WMEM_CHUNK_DATA_LEN(allocator->free_list_head) < size) {
        /* First free chunk isn't big enough. Try the next one. */
        chunk = allocator->free_list_head;
        wmem_block_remove_from_free_list(allocator, chunk);
        if (allocator->free_list_head == NULL ||
                WMEM_CHUNK_DATA_LEN(allocator->free_list_head) < size) {
            /* Next one isn't big enough (or there is no next one) so grab
             * a new block */
            wmem_block_new_block(allocator);
        }
        /* Add the old block back (it may still deserve to be listed, just
         * deprioritized). This is a no-op if it is not large enough. */
        wmem_block_add_to_free_list(allocator, chunk);
    }

    chunk = allocator->free_list_head;

    /* if we still don't have the space at this point, something is wrong */
    g_assert(size <= WMEM_CHUNK_DATA_LEN(chunk));

    /* Split our chunk into two to preserve any trailing free space */
    wmem_block_split_free_chunk(allocator, chunk, size);

    /* if our split reduced our size too much, something went wrong */
    g_assert(size <= WMEM_CHUNK_DATA_LEN(chunk));

    /* the resulting chunk should not be in the free list */
    g_assert(chunk != allocator->free_list_head);
    g_assert(chunk != allocator->free_insert_point);

    /* mark it as used */
    chunk->used = TRUE;

    /* and return the user's pointer */
    return WMEM_CHUNK_DATA(chunk);
}
