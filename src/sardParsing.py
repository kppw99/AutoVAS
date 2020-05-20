#!/usr/bin/env python3

### import library ###
import copy
import logging as log
from tqdm import tqdm
from pyparsing import *
from sardUtil import parseDic, getSnippetFileName, bar_format
from sardUtil import getAPIListFileName, getResultFileName, getTokenFileName

### Global Variable ###
operator =      Literal("=") | Literal("+") | Literal("-") | \
                Literal("*") | Literal("/") | Literal("&") | \
                Literal("<") | Literal(">") | Literal("!") | \
                Literal("?") | Literal("&") | Literal("|") | \
                Literal("~") | Literal("^") | Literal(":") | \
                Literal(".")
bracket =       Literal("[") | Literal("]") | Literal("{") | \
                Literal("}") | Literal("(") | Literal(")")
semiNcomma =    Literal(";") | Literal(",")
specialOp =     ["=#=", "!#=", "&#&", "|#|", "<#=", ">#=",  \
                "+#=", "-#=", "*#=", "/#=", "%#=", "<#<",   \
                ">#>", "-#>", "+#+", "-#-"]
keywords =      ['auto', 'break', 'case', 'char', 'const',      \
                'continue', 'default', 'do', 'double', 'else',  \
                'enum', 'extern', 'float', 'for', 'goto',       \
                'if', 'int', 'long', 'register', 'return',      \
                'short', 'signed', 'sizeof', 'static',          \
                'struct', 'switch', 'typedef', 'union',         \
                'unsigned', 'void', 'volatile', 'while']


### Define API Functions ###
def parsing(debug=False, snippetFile=None, apiListFile=None, resultFile=None,
        loopCnt=0):
    if debug:
        log.basicConfig(level=log.DEBUG)
    if snippetFile is None:
        snippetFile = getSnippetFileName()
    if apiListFile is None:
        apiListFile = getAPIListFileName()
    if resultFile is None:
        resultFile = getResultFileName()

    snippetList = _readSnippets(snippetFile)

    loopCnt = len(snippetList) if loopCnt == 0 else loopCnt
    for snippet in tqdm(snippetList[:loopCnt], desc="[*] Parsing",
            unit_scale=True, bar_format=bar_format):
        _doParse(snippet, apiListFile, resultFile)

def tokening(resultFile=None, tokenFile=None):
    if resultFile is None:
        resultFile = getResultFileName()
    if tokenFile is None:
        tokenFile = getTokenFileName()
    fp = open(resultFile, 'rt')
    for line in fp.readlines():
        temp = line.split("#")
        tokens = temp[3:3+int(temp[-1])]
        srcLine = ' '.join(tokens) + "\n"
        with open(tokenFile, 'at') as f:
            f.write(srcLine)
    fp.close()

### Define Local Functions ###
def _readSnippets(fileName):
    vs = ""
    var = ""
    label = ""
    sourceFile = ""
    src = list()
    funcs = list()
    snippetList = list()
    fp = open(fileName, "rt")
    for line in tqdm(fp.readlines(), desc="[*] Read Snippet",
            unit_scale=True, bar_format=bar_format):
        lineStr = line[:-1]
        if lineStr.find(parseDic["startFile"]) >= 0:
            log.debug("Start File")
            sourceFile = lineStr[len(parseDic["startFile"]) + 1:]
        elif lineStr == parseDic["endFile"]:
            log.debug("End File")
        elif lineStr == parseDic["snippetStart"]:
            log.debug("Start Snippet")
        elif lineStr == parseDic["snippetEnd"]:
            srcTemp = copy.deepcopy(src)
            funcsTemp = copy.deepcopy(funcs)
            snippet = [var, label, vs, srcTemp, funcsTemp, sourceFile]
            snippetList.append(snippet)
            log.debug("End Snippet")
        elif lineStr.find(parseDic["varToken"]) >= 0:
            var = lineStr[len(parseDic["varToken"]) + 2:len(lineStr)-2]
            log.debug("Var Token: " + var)
        elif lineStr.find(parseDic["vsToken"]) >= 0:
            vs = lineStr[len(parseDic["vsToken"]) + 1:len(lineStr)-1]
            del funcs[:]
            log.debug("Vs Token: " + vs)
        elif lineStr.find(parseDic["funcToken"]) >= 0:
            func = lineStr[len(parseDic["funcToken"]) + 1:].split(" ")
            funcs.append(func)
        elif lineStr.find(parseDic["labelToken"]) >= 0:
            label = lineStr[len(parseDic["labelToken"]) + 2:len(lineStr)-2]
            log.debug("Label Token: " + label)
        elif lineStr.find(parseDic["startSRC"]) >= 0:
            log.debug("Start SRC")
            del src[:]
        elif lineStr == parseDic["endSRC"]:
            log.debug("End SRC")
        else:
            src.append(lineStr)
            log.debug(lineStr)
    fp.close()
    return snippetList

def _doParse(snippet, apiListFile, resultFile):
    var, label, vs, src, funcs, sourceFile = _splitSnippetList(snippet)
    tokens = _parsing(vs, src, funcs, apiListFile)
    _writeResultFile(label, sourceFile, var, tokens, resultFile)

def _writeResultFile(label, sourceFile, var, tokens, resultFile):
    temp = label + "#" + sourceFile + "#" + var + "#"
    for token in tokens:
        temp += token + "#"
    temp += str(len(tokens)) + "\n"
    fp = open(resultFile, "at")
    fp.write(temp)
    fp.close()

def _parsing(vs, src, funcs, apiListFile):
    # Remove comments and Tokenizing
    tokens, sNums = _tokenize(_removeComment(src))
    # Parsing and Symbolic Representation for variable
    tokens = _replaceVar(vs, tokens, sNums, funcs)
    # Replace Special Operations
    tokens = _replaceSpecialOp(tokens)
    # Symbolic Representation for func
    tokens = _replaceFunc(tokens, apiListFile)
    return tokens

def _replaceFunc(tokens, apiListFile):
    idx = 0
    allFuncs = list()
    # Get APIList
    apiList = _getAPIList(apiListFile)
    # Make Parse Function
    tmpSrc = "#".join(tokens)
    func = Word(alphanums + "_") + Literal('#(')
    parsing = func("func")
    for fn,s,e in parsing.scanString(tmpSrc):
        if not fn.func[0] in keywords:
            allFuncs.append(fn.func[0])
    allFuncs = list(set(allFuncs))
    # Replace Symbolic Name without apiList
    flag = 0
    for func in allFuncs:
        symbol = "FUNC" + str(idx)
        if not func in apiList:
            tmpSrc = tmpSrc.split("#")
            tempList = list()
            for temp in tmpSrc:
                if temp == func:
                    tempList.append(symbol)
                    flag = 1
                else:
                    tempList.append(temp)
            if flag:
                idx += 1
                flag = 0
            tmpSrc = "#".join(tempList)
    return tmpSrc.split("#")

def _getAPIList(apiListFile):
    fp = open(apiListFile, 'rt')
    funcBuffer = fp.read()
    funcBuffer = funcBuffer.replace(' ', '')
    funcBuffer = funcBuffer.replace('\n', '')
    apiList = funcBuffer.split(',')
    fp.close()
    return apiList

def _replaceSpecialOp(tokens):
    tmpSrc = "#".join(tokens)
    for op in specialOp:
        if tmpSrc.find(op) >= 0:
            tmp = op[0] + op[2]
            tmpSrc = tmpSrc.replace(op, tmp)
    return tmpSrc.split("#")

def _tokenize(src):
    sNums = list()
    tokens = list()
    separator = ZeroOrMore(operator)
    separator += ZeroOrMore(bracket)
    separator += ZeroOrMore(semiNcomma)
    word = Word(alphanums + "_" + "\\" + "\"" + "'")
    parsing = Optional(word("word")) + Optional(separator)
    parsing.ignore("L\"")
    for line in src.split("\n"):
        nIdx = line.find(" ")
        sNum = line[:nIdx]
        srcLine = line[nIdx:].strip()
        for fn,s,e in parsing.scanString(srcLine):
            for token in fn:
                tokens.append(token)
                sNums.append(sNum)
    return tokens, sNums

def _getFuncNums(funcs, funcName):
    sNum = 0
    eNum = 0
    for func in funcs:
        if funcName == func[0]:
            sNum = int(func[1])
            eNum = int(func[2])
            break;
    return sNum, eNum

def _replaceVar(vs, tokens, sNums, funcs):
    idx = 0
    for var in vs:
        idxFlag = idx
        symbol = "VAR" + str(idx)
        varName = var[:var.find("@")]
        funcName = var[var.find("@") + 1:]
        funcStart, funcEnd = _getFuncNums(funcs, funcName)
        for i, token in enumerate(tokens):
            sNum = int(sNums[i])
            if token == varName and sNum >= funcStart and sNum <= funcEnd:
                tokens[i] = symbol
                idxFlag += 1
        if idxFlag != idx: idx += 1
    return tokens

def _removeComment(src):
    lComment = "//"
    while True:
        sIdx = src.find(lComment)
        if sIdx < 0:
            break
        temp =src[sIdx:]
        comment = temp[:temp.find("\n")]
        preSrc = src[:src.find(comment)]
        postSrc = src[len(preSrc) + len(comment):]
        src = preSrc + postSrc
    mSComment = "/*"
    mEComment = "*/"
    while True:
        if src.find(mSComment) < 0:
            break
        preSrc = src[:src.find(mSComment)]
        postSrc = src[src.find(mEComment) + len(mEComment):]
        src = preSrc + postSrc
    return src

def _splitSnippetList(snippet):
    var = snippet[0]
    label = snippet[1]
    vs = snippet[2].replace("'", "").replace(" ", "").split(",")
    src = "\n".join(snippet[3])
    funcs = snippet[4]
    sourceFile = snippet[5]
    return var, label, vs, src, funcs, sourceFile


### execution ###
if __name__=="__main__":
    parsing(loopCnt=188)
    #tokening()
