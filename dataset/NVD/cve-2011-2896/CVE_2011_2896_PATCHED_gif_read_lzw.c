 */

static int				/* I - Byte from stream */
CVE_2011_2896_PATCHED_gif_read_lzw(FILE *fp,			/* I - File to read from */
	     int  first_time,		/* I - 1 = first time, 0 = not first time */
 	     int  input_code_size)	/* I - Code size in bits */
{
  int			i,		/* Looping var */
			code,		/* Current code */
			incode;		/* Input code */
  static short		fresh = 0,	/* 1 = empty buffers */
			code_size,	/* Current code size */
			set_code_size,	/* Initial code size set */
			max_code,	/* Maximum code used */
			max_code_size,	/* Maximum code size */
			firstcode,	/* First code read */
			oldcode,	/* Last code read */
			clear_code,	/* Clear code for LZW input */
			end_code,	/* End code for LZW input */
			*stack = NULL,	/* Output stack */
			*sp;		/* Current stack pointer */
  static gif_table_t	*table = NULL;	/* String table */


  if (first_time)
  {
   /*
    * Setup LZW state...
    */

    set_code_size = input_code_size;
    code_size     = set_code_size + 1;
    clear_code    = 1 << set_code_size;
    end_code      = clear_code + 1;
    max_code_size = 2 * clear_code;
    max_code      = clear_code + 2;

   /*
    * Allocate memory for buffers...
    */

    if (table == NULL)
      table = calloc(2, sizeof(gif_table_t));

    if (table == NULL)
      return (-1);

    if (stack == NULL)
      stack = calloc(8192, sizeof(short));

    if (stack == NULL)
      return (-1);

   /*
    * Initialize input buffers...
    */

    gif_get_code(fp, 0, 1);

   /*
    * Wipe the decompressor table (already mostly 0 due to the calloc above...)
    */

    fresh = 1;

    for (i = 1; i < clear_code; i ++)
      table[1][i] = i;

    sp = stack;

    return (0);
  }
  else if (fresh)
  {
    fresh = 0;

    do
    {
      firstcode = oldcode = gif_get_code(fp, code_size, 0);
    }
    while (firstcode == clear_code);

    return (firstcode & 255);
  }
  else if (!table)
    return (0);

  if (sp > stack)
    return ((*--sp) & 255);

  while ((code = gif_get_code(fp, code_size, 0)) >= 0)
  {
    if (code == clear_code)
    {
     /*
      * Clear/reset the compression table...
      */

      memset(table, 0, 2 * sizeof(gif_table_t));
      for (i = 1; i < clear_code; i ++)
	table[1][i] = i;

      code_size     = set_code_size + 1;
      max_code_size = 2 * clear_code;
      max_code      = clear_code + 2;

      sp = stack;

      firstcode = oldcode = gif_get_code(fp, code_size, 0);

      return (firstcode & 255);
    }
    else if (code == end_code || code > max_code)
    {
      unsigned char	buf[260];	/* Block buffer */

      if (!gif_eof)
        while (gif_get_block(fp, buf) > 0);

      return (-2);
    }

    incode = code;

    if (code == max_code)
    {
      *sp++ = firstcode;
      code  = oldcode;
    }

    while (code >= clear_code)
    {
      *sp++ = table[1][code];
      if (code == table[0][code])
	return (255);

      code = table[0][code];
    }

    *sp++ = firstcode = table[1][code];
    code  = max_code;

    if (code < 4096)
    {
      table[0][code] = oldcode;
      table[1][code] = firstcode;
      max_code ++;

      if (max_code >= max_code_size && max_code_size < 4096)
      {
	max_code_size *= 2;
	code_size ++;
      }
    }

    oldcode = incode;

    if (sp > stack)
      return ((*--sp) & 255);
  }

  return (code & 255);
}
