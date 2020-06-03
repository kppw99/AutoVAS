  static FT_Error
  CVE_2009_0946_PATCHED_cff_charset_load( CFF_Charset  charset,
                    FT_UInt      num_glyphs,
                    FT_Stream    stream,
                    FT_ULong     base_offset,
                    FT_ULong     offset,
                    FT_Bool      invert )
  {
    FT_Memory  memory = stream->memory;
    FT_Error   error  = CFF_Err_Ok;
    FT_UShort  glyph_sid;


    /* If the the offset is greater than 2, we have to parse the */
    /* charset table.                                            */
    if ( offset > 2 )
    {
      FT_UInt  j;


      charset->offset = base_offset + offset;

      /* Get the format of the table. */
      if ( FT_STREAM_SEEK( charset->offset ) ||
           FT_READ_BYTE( charset->format )   )
        goto Exit;

      /* Allocate memory for sids. */
      if ( FT_NEW_ARRAY( charset->sids, num_glyphs ) )
        goto Exit;

      /* assign the .notdef glyph */
      charset->sids[0] = 0;

      switch ( charset->format )
      {
      case 0:
        if ( num_glyphs > 0 )
        {
          if ( FT_FRAME_ENTER( ( num_glyphs - 1 ) * 2 ) )
            goto Exit;

          for ( j = 1; j < num_glyphs; j++ )
          {
            FT_UShort sid = FT_GET_USHORT();


            /* this constant is given in the CFF specification */
            if ( sid < 65000 )
              charset->sids[j] = sid;
            else
            {
              FT_ERROR(( "CVE_2009_0946_PATCHED_cff_charset_load:"
                         " invalid SID value %d set to zero\n", sid ));
              charset->sids[j] = 0;
            }
          }

          FT_FRAME_EXIT();
        }
        break;

      case 1:
      case 2:
        {
          FT_UInt  nleft;
          FT_UInt  i;


          j = 1;

          while ( j < num_glyphs )
          {
            /* Read the first glyph sid of the range. */
            if ( FT_READ_USHORT( glyph_sid ) )
              goto Exit;

            /* Read the number of glyphs in the range.  */
            if ( charset->format == 2 )
            {
              if ( FT_READ_USHORT( nleft ) )
                goto Exit;
            }
            else
            {
              if ( FT_READ_BYTE( nleft ) )
                goto Exit;
            }

            /* check whether the range contains at least one valid glyph; */
            /* the constant is given in the CFF specification             */
            if ( glyph_sid >= 65000 ) {
              FT_ERROR(( "CVE_2009_0946_PATCHED_cff_charset_load: invalid SID range\n" ));
              error = CFF_Err_Invalid_File_Format;
              goto Exit;
            }

            /* try to rescue some of the SIDs if `nleft' is too large */
            if ( nleft > 65000 - 1 || glyph_sid >= 65000 - nleft ) {
              FT_ERROR(( "CVE_2009_0946_PATCHED_cff_charset_load: invalid SID range trimmed\n" ));
              nleft = 65000 - 1 - glyph_sid;
            }

            /* Fill in the range of sids -- `nleft + 1' glyphs. */
            for ( i = 0; j < num_glyphs && i <= nleft; i++, j++, glyph_sid++ )
              charset->sids[j] = glyph_sid;
          }
        }
        break;

      default:
        FT_ERROR(( "CVE_2009_0946_PATCHED_cff_charset_load: invalid table format!\n" ));
        error = CFF_Err_Invalid_File_Format;
        goto Exit;
      }
    }
    else
    {
      /* Parse default tables corresponding to offset == 0, 1, or 2.  */
      /* CFF specification intimates the following:                   */
      /*                                                              */
      /* In order to use a predefined charset, the following must be  */
      /* true: The charset constructed for the glyphs in the font's   */
      /* charstrings dictionary must match the predefined charset in  */
      /* the first num_glyphs.                                        */

      charset->offset = offset;  /* record charset type */

      switch ( (FT_UInt)offset )
      {
      case 0:
        if ( num_glyphs > 229 )
        {
          FT_ERROR(( "CVE_2009_0946_PATCHED_cff_charset_load: implicit charset larger than\n"
                     "predefined charset (Adobe ISO-Latin)!\n" ));
          error = CFF_Err_Invalid_File_Format;
          goto Exit;
        }

        /* Allocate memory for sids. */
        if ( FT_NEW_ARRAY( charset->sids, num_glyphs ) )
          goto Exit;

        /* Copy the predefined charset into the allocated memory. */
        FT_ARRAY_COPY( charset->sids, cff_isoadobe_charset, num_glyphs );

        break;

      case 1:
        if ( num_glyphs > 166 )
        {
          FT_ERROR(( "CVE_2009_0946_PATCHED_cff_charset_load: implicit charset larger than\n"
                     "predefined charset (Adobe Expert)!\n" ));
          error = CFF_Err_Invalid_File_Format;
          goto Exit;
        }

        /* Allocate memory for sids. */
        if ( FT_NEW_ARRAY( charset->sids, num_glyphs ) )
          goto Exit;

        /* Copy the predefined charset into the allocated memory.     */
        FT_ARRAY_COPY( charset->sids, cff_expert_charset, num_glyphs );

        break;

      case 2:
        if ( num_glyphs > 87 )
        {
          FT_ERROR(( "CVE_2009_0946_PATCHED_cff_charset_load: implicit charset larger than\n"
                     "predefined charset (Adobe Expert Subset)!\n" ));
          error = CFF_Err_Invalid_File_Format;
          goto Exit;
        }

        /* Allocate memory for sids. */
        if ( FT_NEW_ARRAY( charset->sids, num_glyphs ) )
          goto Exit;

        /* Copy the predefined charset into the allocated memory.     */
        FT_ARRAY_COPY( charset->sids, cff_expertsubset_charset, num_glyphs );

        break;

      default:
        error = CFF_Err_Invalid_File_Format;
        goto Exit;
      }
    }

    /* we have to invert the `sids' array for subsetted CID-keyed fonts */
    if ( invert )
      error = cff_charset_compute_cids( charset, num_glyphs, memory );

  Exit:
    /* Clean up if there was an error. */
    if ( error )
    {
      FT_FREE( charset->sids );
      FT_FREE( charset->cids );
      charset->format = 0;
      charset->offset = 0;
      charset->sids   = 0;
    }

    return error;
  }
