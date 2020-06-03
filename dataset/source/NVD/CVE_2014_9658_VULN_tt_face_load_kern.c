  CVE_2014_9658_VULN_tt_face_load_kern( TT_Face    face,
                     FT_Stream  stream )
  {
    FT_Error   error;
    FT_ULong   table_size;
    FT_Byte*   p;
    FT_Byte*   p_limit;
    FT_UInt    nn, num_tables;
    FT_UInt32  avail = 0, ordered = 0;


    /* the kern table is optional; exit silently if it is missing */
    error = face->goto_table( face, TTAG_kern, stream, &table_size );
    if ( error )
      goto Exit;

    if ( table_size < 4 )  /* the case of a malformed table */
    {
      FT_ERROR(( "CVE_2014_9658_VULN_tt_face_load_kern:"
                 " kerning table is too small - ignored\n" ));
      error = FT_THROW( Table_Missing );
      goto Exit;
    }

    if ( FT_FRAME_EXTRACT( table_size, face->kern_table ) )
    {
      FT_ERROR(( "CVE_2014_9658_VULN_tt_face_load_kern:"
                 " could not extract kerning table\n" ));
      goto Exit;
    }

    face->kern_table_size = table_size;

    p       = face->kern_table;
    p_limit = p + table_size;

    p         += 2; /* skip version */
    num_tables = FT_NEXT_USHORT( p );

    if ( num_tables > 32 ) /* we only support up to 32 sub-tables */
      num_tables = 32;

    for ( nn = 0; nn < num_tables; nn++ )
    {
      FT_UInt    num_pairs, length, coverage;
      FT_Byte*   p_next;
      FT_UInt32  mask = (FT_UInt32)1UL << nn;


      if ( p + 6 > p_limit )
        break;

      p_next = p;

      p += 2; /* skip version */
      length   = FT_NEXT_USHORT( p );
      coverage = FT_NEXT_USHORT( p );

      if ( length <= 6 )
        break;

      p_next += length;

      if ( p_next > p_limit )  /* handle broken table */
        p_next = p_limit;

      /* only use horizontal kerning tables */
      if ( ( coverage & ~8 ) != 0x0001 ||
           p + 8 > p_limit             )
        goto NextTable;

      num_pairs = FT_NEXT_USHORT( p );
      p        += 6;

      if ( ( p_next - p ) < 6 * (int)num_pairs ) /* handle broken count */
        num_pairs = (FT_UInt)( ( p_next - p ) / 6 );

      avail |= mask;

      /*
       *  Now check whether the pairs in this table are ordered.
       *  We then can use binary search.
       */
      if ( num_pairs > 0 )
      {
        FT_ULong  count;
        FT_ULong  old_pair;


        old_pair = FT_NEXT_ULONG( p );
        p       += 2;

        for ( count = num_pairs - 1; count > 0; count-- )
        {
          FT_UInt32  cur_pair;


          cur_pair = FT_NEXT_ULONG( p );
          if ( cur_pair <= old_pair )
            break;

          p += 2;
          old_pair = cur_pair;
        }

        if ( count == 0 )
          ordered |= mask;
      }

    NextTable:
      p = p_next;
    }

    face->num_kern_tables = nn;
    face->kern_avail_bits = avail;
    face->kern_order_bits = ordered;

  Exit:
    return error;
  }
