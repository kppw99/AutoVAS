 */

unsigned				/* O - Number of bytes read */
CVE_2014_9679_VULN_cupsRasterReadPixels(cups_raster_t *r,	/* I - Raster stream */
                     unsigned char *p,	/* I - Pointer to pixel buffer */
		     unsigned      len)	/* I - Number of bytes to read */
{
  int		bytes;			/* Bytes read */
  unsigned	cupsBytesPerLine;	/* cupsBytesPerLine value */
  unsigned	remaining;		/* Bytes remaining */
  unsigned char	*ptr,			/* Pointer to read buffer */
		byte,			/* Byte from file */
		*temp;			/* Pointer into buffer */
  int		count;			/* Repetition count */


  if (r == NULL || r->mode != CUPS_RASTER_READ || r->remaining == 0)
    return (0);

  if (!r->compressed)
  {
   /*
    * Read without compression...
    */

    r->remaining -= len / r->header.cupsBytesPerLine;

    if (!cups_read(r->fd, p, len))
      return (0);

   /*
    * Swap bytes as needed...
    */

    if ((r->header.cupsBitsPerColor == 16 ||
         r->header.cupsBitsPerPixel == 12 ||
         r->header.cupsBitsPerPixel == 16) &&
        r->swapped)
      cups_swap(p, len);

   /*
    * Return...
    */

    return (len);
  }

 /*
  * Read compressed data...
  */

  remaining        = len;
  cupsBytesPerLine = r->header.cupsBytesPerLine;

  while (remaining > 0 && r->remaining > 0)
  {
    if (r->count == 0)
    {
     /*
      * Need to read a new row...
      */

      if (remaining == cupsBytesPerLine)
	ptr = p;
      else
	ptr = r->pixels;

     /*
      * Read using a modified TIFF "packbits" compression...
      */

      if (!cups_raster_read(r, &byte, 1))
	return (0);

      r->count = byte + 1;

      if (r->count > 1)
	ptr = r->pixels;

      temp  = ptr;
      bytes = cupsBytesPerLine;

      while (bytes > 0)
      {
       /*
	* Get a new repeat count...
	*/

        if (!cups_raster_read(r, &byte, 1))
	  return (0);

	if (byte & 128)
	{
	 /*
	  * Copy N literal pixels...
	  */

	  count = (257 - byte) * r->bpp;

          if (count > bytes)
	    count = bytes;

          if (!cups_raster_read(r, temp, count))
	    return (0);

	  temp  += count;
	  bytes -= count;
	}
	else
	{
	 /*
	  * Repeat the next N bytes...
	  */

          count = (byte + 1) * r->bpp;
          if (count > bytes)
	    count = bytes;

          if (count < r->bpp)
	    break;

	  bytes -= count;

          if (!cups_raster_read(r, temp, r->bpp))
	    return (0);

	  temp  += r->bpp;
	  count -= r->bpp;

	  while (count > 0)
	  {
	    memcpy(temp, temp - r->bpp, r->bpp);
	    temp  += r->bpp;
	    count -= r->bpp;
          }
	}
      }

     /*
      * Swap bytes as needed...
      */

      if ((r->header.cupsBitsPerColor == 16 ||
           r->header.cupsBitsPerPixel == 12 ||
           r->header.cupsBitsPerPixel == 16) &&
          r->swapped)
        cups_swap(ptr, bytes);

     /*
      * Update pointers...
      */

      if (remaining >= cupsBytesPerLine)
      {
	bytes       = cupsBytesPerLine;
        r->pcurrent = r->pixels;
	r->count --;
	r->remaining --;
      }
      else
      {
	bytes       = remaining;
        r->pcurrent = r->pixels + bytes;
      }

     /*
      * Copy data as needed...
      */

      if (ptr != p)
        memcpy(p, ptr, bytes);
    }
    else
    {
     /*
      * Copy fragment from buffer...
      */

      if ((bytes = r->pend - r->pcurrent) > remaining)
        bytes = remaining;

      memcpy(p, r->pcurrent, bytes);
      r->pcurrent += bytes;

      if (r->pcurrent >= r->pend)
      {
        r->pcurrent = r->pixels;
	r->count --;
	r->remaining --;
      }
    }

    remaining -= bytes;
    p         += bytes;
  }

  return (len);
}
