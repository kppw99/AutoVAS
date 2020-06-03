nsresult
CVE_2012_3972_VULN_txFormatNumberFunctionCall::evaluate(txIEvalContext* aContext,
                                     txAExprResult** aResult)
{
    *aResult = nsnull;
    if (!requireParams(2, 3, aContext))
        return NS_ERROR_XPATH_BAD_ARGUMENT_COUNT;

    // Get number and format
    double value;
    txExpandedName formatName;

    nsresult rv = evaluateToNumber(mParams[0], aContext, &value);
    NS_ENSURE_SUCCESS(rv, rv);

    nsAutoString formatStr;
    rv = mParams[1]->evaluateToString(aContext, formatStr);
    NS_ENSURE_SUCCESS(rv, rv);

    if (mParams.Length() == 3) {
        nsAutoString formatQName;
        rv = mParams[2]->evaluateToString(aContext, formatQName);
        NS_ENSURE_SUCCESS(rv, rv);

        rv = formatName.init(formatQName, mMappings, false);
        NS_ENSURE_SUCCESS(rv, rv);
    }

    txDecimalFormat* format = mStylesheet->getDecimalFormat(formatName);
    if (!format) {
        nsAutoString err(NS_LITERAL_STRING("unknown decimal format"));
#ifdef TX_TO_STRING
        err.AppendLiteral(" for: ");
        toString(err);
#endif
        aContext->receiveError(err, NS_ERROR_XPATH_INVALID_ARG);
        return NS_ERROR_XPATH_INVALID_ARG;
    }

    // Special cases
    if (MOZ_DOUBLE_IS_NaN(value)) {
        return aContext->recycler()->getStringResult(format->mNaN, aResult);
    }

    if (value == MOZ_DOUBLE_POSITIVE_INFINITY()) {
        return aContext->recycler()->getStringResult(format->mInfinity,
                                                     aResult);
    }

    if (value == MOZ_DOUBLE_NEGATIVE_INFINITY()) {
        nsAutoString res;
        res.Append(format->mMinusSign);
        res.Append(format->mInfinity);
        return aContext->recycler()->getStringResult(res, aResult);
    }
    
    // Value is a normal finite number
    nsAutoString prefix;
    nsAutoString suffix;
    int minIntegerSize=0;
    int minFractionSize=0;
    int maxFractionSize=0;
    int multiplier=1;
    int groupSize=-1;

    PRUint32 pos = 0;
    PRUint32 formatLen = formatStr.Length();
    bool inQuote;

    // Get right subexpression
    inQuote = false;
    if (MOZ_DOUBLE_IS_NEGATIVE(value)) {
        while (pos < formatLen &&
               (inQuote ||
                formatStr.CharAt(pos) != format->mPatternSeparator)) {
            if (formatStr.CharAt(pos) == FORMAT_QUOTE)
                inQuote = !inQuote;
            pos++;
        }

        if (pos == formatLen) {
            pos = 0;
            prefix.Append(format->mMinusSign);
        }
        else
            pos++;
    }

    // Parse the format string
    FormatParseState pState = Prefix;
    inQuote = false;

    PRUnichar c = 0;
    while (pos < formatLen && pState != Finished) {
        c=formatStr.CharAt(pos++);

        switch (pState) {

        case Prefix:
        case Suffix:
            if (!inQuote) {
                if (c == format->mPercent) {
                    if (multiplier == 1)
                        multiplier = 100;
                    else {
                        nsAutoString err(INVALID_PARAM_VALUE);
#ifdef TX_TO_STRING
                        err.AppendLiteral(": ");
                        toString(err);
#endif
                        aContext->receiveError(err,
                                               NS_ERROR_XPATH_INVALID_ARG);
                        return NS_ERROR_XPATH_INVALID_ARG;
                    }
                }
                else if (c == format->mPerMille) {
                    if (multiplier == 1)
                        multiplier = 1000;
                    else {
                        nsAutoString err(INVALID_PARAM_VALUE);
#ifdef TX_TO_STRING
                        err.AppendLiteral(": ");
                        toString(err);
#endif
                        aContext->receiveError(err,
                                               NS_ERROR_XPATH_INVALID_ARG);
                        return NS_ERROR_XPATH_INVALID_ARG;
                    }
                }
                else if (c == format->mDecimalSeparator ||
                         c == format->mGroupingSeparator ||
                         c == format->mZeroDigit ||
                         c == format->mDigit ||
                         c == format->mPatternSeparator) {
                    pState = pState == Prefix ? IntDigit : Finished;
                    pos--;
                    break;
                }
            }

            if (c == FORMAT_QUOTE)
                inQuote = !inQuote;
            else if (pState == Prefix)
                prefix.Append(c);
            else
                suffix.Append(c);
            break;

        case IntDigit:
            if (c == format->mGroupingSeparator)
                groupSize=0;
            else if (c == format->mDigit) {
                if (groupSize >= 0)
                    groupSize++;
            }
            else {
                pState = IntZero;
                pos--;
            }
            break;

        case IntZero:
            if (c == format->mGroupingSeparator)
                groupSize = 0;
            else if (c == format->mZeroDigit) {
                if (groupSize >= 0)
                    groupSize++;
                minIntegerSize++;
            }
            else if (c == format->mDecimalSeparator) {
                pState = FracZero;
            }
            else {
                pState = Suffix;
                pos--;
            }
            break;

        case FracZero:
            if (c == format->mZeroDigit) {
                maxFractionSize++;
                minFractionSize++;
            }
            else {
                pState = FracDigit;
                pos--;
            }
            break;

        case FracDigit:
            if (c == format->mDigit)
                maxFractionSize++;
            else {
                pState = Suffix;
                pos--;
            }
            break;

        case Finished:
            break;
        }
    }

    // Did we manage to parse the entire formatstring and was it valid
    if ((c != format->mPatternSeparator && pos < formatLen) ||
        inQuote ||
        groupSize == 0) {
        nsAutoString err(INVALID_PARAM_VALUE);
#ifdef TX_TO_STRING
        err.AppendLiteral(": ");
        toString(err);
#endif
        aContext->receiveError(err, NS_ERROR_XPATH_INVALID_ARG);
        return NS_ERROR_XPATH_INVALID_ARG;
    }


    /*
     * FINALLY we're done with the parsing
     * now build the result string
     */

    value = fabs(value) * multiplier;

    // Prefix
    nsAutoString res(prefix);

    int bufsize;
    if (value > 1)
        bufsize = (int)log10(value) + 30;
    else
        bufsize = 1 + 30;

    char* buf = new char[bufsize];
    NS_ENSURE_TRUE(buf, NS_ERROR_OUT_OF_MEMORY);

    PRIntn bufIntDigits, sign;
    char* endp;
    PR_dtoa(value, 0, 0, &bufIntDigits, &sign, &endp, buf, bufsize-1);

    int buflen = endp - buf;
    int intDigits;
    intDigits = bufIntDigits > minIntegerSize ? bufIntDigits : minIntegerSize;

    if (groupSize < 0)
        groupSize = intDigits + 10; //to simplify grouping

    // XXX We shouldn't use SetLength.
    res.SetLength(res.Length() +
                  intDigits +               // integer digits
                  1 +                       // decimal separator
                  maxFractionSize +         // fractions
                  (intDigits-1)/groupSize); // group separators

    PRInt32 i = bufIntDigits + maxFractionSize - 1;
    bool carry = (i+1 < buflen) && (buf[i+1] >= '5');
    bool hasFraction = false;

    PRUint32 resPos = res.Length()-1;

    // Fractions
    for (; i >= bufIntDigits; --i) {
        int digit;
        if (i >= buflen || i < 0) {
            digit = 0;
        }
        else {
            digit = buf[i] - '0';
        }
        
        if (carry) {
            digit = (digit + 1) % 10;
            carry = digit == 0;
        }

        if (hasFraction || digit != 0 || i < bufIntDigits+minFractionSize) {
            hasFraction = true;
            res.SetCharAt((PRUnichar)(digit + format->mZeroDigit),
                          resPos--);
        }
        else {
            res.Truncate(resPos--);
        }
    }

    // Decimal separator
    if (hasFraction) {
        res.SetCharAt(format->mDecimalSeparator, resPos--);
    }
    else {
        res.Truncate(resPos--);
    }

    // Integer digits
    for (i = 0; i < intDigits; ++i) {
        int digit;
        if (bufIntDigits-i-1 >= buflen || bufIntDigits-i-1 < 0) {
            digit = 0;
        }
        else {
            digit = buf[bufIntDigits-i-1] - '0';
        }
        
        if (carry) {
            digit = (digit + 1) % 10;
            carry = digit == 0;
        }

        if (i != 0 && i%groupSize == 0) {
            res.SetCharAt(format->mGroupingSeparator, resPos--);
        }

        res.SetCharAt((PRUnichar)(digit + format->mZeroDigit), resPos--);
    }

    if (carry) {
        if (i%groupSize == 0) {
            res.Insert(format->mGroupingSeparator, resPos + 1);
        }
        res.Insert((PRUnichar)(1 + format->mZeroDigit), resPos + 1);
    }
    
    if (!hasFraction && !intDigits && !carry) {
        // If we havn't added any characters we add a '0'
        // This can only happen for formats like '##.##'
        res.Append(format->mZeroDigit);
    }

    delete [] buf;

    // Build suffix
    res.Append(suffix);

    return aContext->recycler()->getStringResult(res, aResult);
} //-- evaluate
