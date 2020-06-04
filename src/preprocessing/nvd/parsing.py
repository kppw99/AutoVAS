#!/usr/bin/env python3

import os, json
from util import *
from tqdm import tqdm
from pyparsing import *


_SEP = '------------------------------\n'

operator =      Literal("=") | Literal("+") | Literal("-") | \
                Literal("*") | Literal("/") | Literal("&") | \
                Literal("<") | Literal(">") | Literal("!") | \
                Literal("?") | Literal("&") | Literal("|") | \
                Literal("~") | Literal("^") | Literal(":") | \
                Literal(".")

bracket =       Literal("[") | Literal("]") | Literal("{") | \
                Literal("}") | Literal("(") | Literal(")")

semiNcomma =    Literal(";") | Literal(",")

dualop =    Literal("==") | Literal("!=") | Literal("&&") | Literal("||") | \
            Literal("<=") | Literal(">=") | Literal("+=") | Literal("-=") | \
            Literal("*=") | Literal("/=") | Literal("%=") | Literal("<<") | \
            Literal(">>") | Literal("->") | Literal("++") | Literal("--")

separators = [
    "=", "+", "-", "*", "/", "&", "<", ">", "!", "?", "&", "|",
    "~", "^", ":", ".", "[", "]", "{", "}", "(", ")", ";", ","
]

specialOp =     ["==", "!=", "&&", "||", "<=", ">=",  \
                "+=", "-=", "*=", "/=", "%=", "<<",   \
                ">>", "->", "++", "--"]

keywords =      ['auto', 'break', 'case', 'char', 'const',      \
                'continue', 'default', 'do', 'double', 'else',  \
                'enum', 'extern', 'float', 'for', 'goto',       \
                'if', 'int', 'long', 'register', 'return',      \
                'short', 'signed', 'sizeof', 'static',          \
                'struct', 'switch', 'typedef', 'union',         \
                'unsigned', 'void', 'volatile', 'while']


def _tokenize(items):
    tokens = list()
    iden = Word(alphanums + "_" + "\"" + "'")
    separator = ZeroOrMore(dualop)
    separator += ZeroOrMore(operator)
    separator += ZeroOrMore(bracket)
    separator += ZeroOrMore(semiNcomma)
    parsing = Optional(separator) + Optional(iden) + Optional(separator)
    for item, s, e in parsing.scanString(items):
        tokens.extend(item)
    return tokens

def _replaceVar(tokens, vars):
    idx = 0
    for var in vars:
        idxFlag = idx
        symbol = "VAR" + str(idx)
        for i, token in enumerate(tokens):
            if token == var:
                tokens[i] = symbol
                idxFlag += 1
        if idxFlag != idx: idx += 1
    return tokens

def _replaceFunc(tokens, methods):
    idx = 0
    apiList = getAPIListFileName()
    funcList = [x for x in methods if not x in apiList]
    for func in funcList:
        idxFlag = idx
        symbol = "FUNC" + str(idx)
        for i, token in enumerate(tokens):
            if token == func:
                tokens[i] = symbol
                idxFlag += 1
        if idxFlag != idx: idx += 1
    return tokens

def tokenize(item):
    if len(item) == 1:                          # a
        return [item]
    elif len(item) == 2 and item[1] == ';':     # a;
        return [item[0], item[1]]
    elif len(item) == 3 and item[2] == ';' and item[0:2] in specialOp:  # ++;
        return [item[0:2], item[2]]
    elif item[0] == "\"" and item[-1] == "\"":  # string
        return [item]
    elif len(item) == 2 and item in specialOp:  # special operation
        return [item]
    elif not any(format in item for format in separators):  # only one variable without separator
        return [item]

    return _tokenize(item)

def loadParsingData():
    print('[*] Start to load json parsing data')
    fileList = getCpgParsingList()
    parsingList = list()
    for filename in tqdm(fileList):
        if os.path.isfile(filename):
            parsingList.append(json.load(open(filename)))
        else:
            print("Please check the file name: %s" % filename)
    return mergeDict(parsingList)

def loadSnippetData():
    print('[*] Start to load snippet data')
    retVal = list()
    with open(getSnippetFileName(), 'r') as f:
        lines = f.readlines()
        for line in tqdm(lines):
            line = line.split('\n')[0]
            retVal.append(line.split('#'))
    return retVal

def makeSnippet():
    print('[*] Start to make nvd snippet file')

    fp = open(getSnippetFileName(), 'w')

    sniPosCnt, sniNegCnt = 0, 0
    inputFiles = getSlicingList()
    for filename in inputFiles:
        with open(filename, 'r') as f:
            print('[-] read splicing file: %s' % filename)
            strList = list()
            tempLine = list()
            snippetFlag, posCnt, negCnt = 0, 0, 0

            lines = f.readlines()
            for line in tqdm(lines):
                lineList = line.split()
                if snippetFlag == 0:
                    filepath = lineList[1]
                    filepath = filepath.split('/')
                    filepath = filepath[1]
                    snippetFlag = 1
                    continue

                tempLine.extend(lineList)

                if line == _SEP:
                    resultLine = list()
                    tempLine = tempLine[:-1]    # eliminate SEP
                    label = tempLine[-1]        # parse label
                    tempLine = tempLine[:-1]    # eliminate SEP

                    if label == '0':
                        posCnt += 1
                        sniPosCnt += 1
                    elif label == '1':
                        negCnt += 1
                        sniNegCnt += 1
                    else:
                        print('label error!!!')
                        break

                    for item in tempLine:
                        strList.extend(tokenize(item))

                    resultLine.append(label)
                    resultLine.append(filepath)
                    resultLine.extend(strList)
                    resultLine.append(str(len(strList)))
                    strLine = '#'.join(resultLine) + '\n'

                    fp.write(strLine)

                    strList.clear()
                    tempLine.clear()
                    snippetFlag = 0
            print('[-] Positive Cnt: %d (%.2f)' % (posCnt, (posCnt / (posCnt + negCnt))))
            print('[-] Negative Cnt: %d (%.2f)' % (negCnt, (negCnt / (posCnt + negCnt))))
            print('------------------------------')
            posCnt, negCnt = 0, 0

    print('[-] Total SnippetCnt: %d' % (sniPosCnt + sniNegCnt))
    print('[-] Positive Snippet: %d (%.2f)' % (sniPosCnt, (sniPosCnt / (sniPosCnt + sniNegCnt))))
    print('[-] Negative Snippet: %d (%.2f)' % (sniNegCnt, (sniNegCnt / (sniPosCnt + sniNegCnt))))
    fp.close()

def parsing():
    print('[*] Start parsing to create nvd result file')
    parseData = loadParsingData()
    targets = list(parseData.keys())
    
    fp = open(getNVDResultFileName(), 'w')
    snippetData = loadSnippetData()
    for snippet in tqdm(snippetData):
        temp = list()
        label = snippet[0]
        targetfile = snippet[1]
        tokens = snippet[2:-1]
        tokenCnt = snippet[-1]
        if targetfile in targets:
            target = parseData[targetfile]['target']
            vars = parseData[targetfile]['vars']
            methods = parseData[targetfile]['methods']
            tokens = _replaceVar(tokens, vars)
            tokens = _replaceFunc(tokens, methods)
        temp.append(label)
        temp.append(targetfile)
        temp.extend(tokens)
        temp.append(str(len(tokens)))
        tempStr = '#'.join(temp) + '\n'
        fp.write(tempStr)
    fp.close()

def run():
    #parseData = loadParsingData()
    #makeSnippet()
    parsing()


if __name__=='__main__':
    run()
