#!/usr/bin/env python3

### import library ###
import sardUtil as util
import os, subprocess, copy
from tqdm import tqdm
from datetime import datetime
from operator import itemgetter

### Global Variable ###
funcFlag = 0
snippetCnt = 0
snippetList = list()


### Define API Functions ###
def slicing(snippetFile=None):
    if snippetFile is None:
        snippetFile = util.getSnippetFileName()
    targets = util.getTargetList()
    _makeSnippet(targets, snippetFile)
    return snippetCnt
    
### Define Local Functions ###
def _slicingTargets(targets):
    global snippetList
    for target in tqdm(targets, desc="[*] Slicing", unit_scale=True,
            bar_format=util.bar_format):
        _slicing(target)
    return snippetList

def _makeSnippet(targets, snippetFile):
    snippetList = _slicingTargets(targets)
    util.setCaptureLog(snippetFile)
    for snippetInfo in snippetList:
        if not _snippetCode(snippetInfo):
            print("Error make SnippetCode function!")
            exit(1)
    util.clearCaptureLog()

def _findFuncName(line, funcName):
    tokens = line.split(' ')
    for token in tokens:
        if funcName in token:
            temp = token
            break
    temp = temp.split('(')[0]
    if temp == funcName:
        return True
    else:
        return False

def _findFunc(fileName, func):
    fp = open(fileName, 'rt')
    lineNum = 0;
    start = 0
    end = 0
    flag = 0
    for line in fp.readlines():
        lineNum += 1
        if func in line and line.find(";") < 0 and line.find("/") < 0:
            if _findFuncName(line, func):
                start = lineNum
        if start != 0 and (line.find("{") >= 0 or line.find("}") >= 0):
            if line.find("{") >= 0:
                flag += 1
            if line.find("}") >= 0:
                flag -= 1
                if flag == 0:
                    end = lineNum
                    break
    fp.close()
    return start, end

def _isVariable(line):
    if line.find("@") >= 0:
        if line.find("main") < 0:
            if line.index("}") - line.index("{") > 1:
                return True
    return False

def _doSlicingCmd(fileName, cmd, inLst, funcs):
    global funcFlag
    try:
        data = subprocess.check_output(cmd, stderr=subprocess.PIPE)
        lst = data.decode('utf-8').split('\n')
        for line in lst:
            tLen = 0
            # Parsing Variable
            if _isVariable(line) == True:
                for tLine in inLst:
                    if line.split()[0] in tLine:
                        if line.split()[2][1:-3] != "":
                            tLine[1].extend(line.split()[2][1:-3].split(','))
                            tLine[1].extend(line.split()[2][1:-3].split(','))
                            break
                    else:
                        tLen += 1
                if tLen == len(inLst):
                    if line.split()[2][1:-3] != "":
                        inLst.append([line.split()[0],
                            line.split()[2][1:-3].split(',')])
            #i Parsing Function List (one time per source file -> funcFlag)
            elif line.find("CFG(#Nodes,#Edges)") >= 0 and funcFlag == 0:
                sNum = line.find("[") + 1
                eNum = line.find("]")
                tmps = line[sNum:eNum].replace("\"", "").split(",")
                for func in tmps:
                    if func.find(":") >= 0:
                        tmp = func[:func.find(":")]
                        s, e = _findFunc(fileName, tmp)
                        funcs.append([tmp, s, e])
                funcFlag = 1
        return True
    except subprocess.CalledProcessError as error:
        errFileName = util.getErrorFileName()
        fp = open(errFileName, 'at')
        now = datetime.now()
        timeStamp = "[{}-{}-{} {}:{}:{}] ".format(now.year,
                str(now.month).zfill(2), str(now.day).zfill(2),
                str(now.hour).zfill(2), str(now.minute).zfill(2),
                str(now.second).zfill(2))
        fp.write(timeStamp + ' '.join(cmd) + '\n')
        fp.close()
        return False

def _doSlicing(fileName, method, inLst, funcs):
    cmd = ['llvm-slicing', '-d', '', '-m', '', fileName]
    if not os.path.isfile(fileName):
        print("Please check the fileName")
        return False
    if method == "IFDS":
        cmd[4] = 'IFDS'
    else:
        cmd[4] = 'Symbolic'
    cmd[2] = 'Fwd'
    if not _doSlicingCmd(fileName, cmd, inLst, funcs):
        return False
    cmd[2] = 'Bwd'
    if not _doSlicingCmd(fileName, cmd, inLst, funcs):
        return False
    return True

def _doLabeling(lst):
    label = 0
    global snippetCnt
    tmp = copy.deepcopy(lst)
    del lst[:]
    for line in tmp:
        if line[0].find("good") >= 0:
            label = 0
        elif line[0].find("bad") >= 0:
            label = 1
        else:
            label = 2
        lst.append([line[0], sorted(set(line[1])), label])
    snippetCnt += len(lst)
    lst.sort(key=itemgetter(0))

def _slicing(fileName):
    global funcFlag
    global snippetList
    funcFlag = 0
    funcs = list()
    snippet = list()
    variables = list()
    # Verifying the fileName
    if not os.path.isfile(fileName):
        print("Please check the fileName")
        return False
    # Slicing (symbolic and IFDS)
    if not _doSlicing(fileName, "Symbolic", snippet, funcs):
        return False
    if not _doSlicing(fileName, "IFDS", snippet, funcs):
        return False
    # Labeling with eliminating duplication lines and sorting line
    _doLabeling(snippet)
    # Adding all variables in file
    for var in snippet:
        temp = var[0].find("@")
        variables.append(var[0])
    # Adding fileName and snippet to the snippetList
    snippetList.append([fileName, variables, snippet, funcs])
    snippetList.sort(key=itemgetter(0))
    return True

def _snippetCode(lst):
    fileName = lst[0]
    variables = lst[1]
    varName = lst[2]
    funcs = lst[3]
    #file open
    if os.path.isfile(fileName) != True:
        print("Please check the fileName!!!")
        return bool(False)
    print("#FILE_START#", fileName)
    for var in varName:
        print("##SNIPPET_START##")
        print("###VAR[ " + var[0] + " ]")
        print("###VS" + str(variables))
        for func in funcs:
            print("###FUNCINFO " + func[0], str(func[1]), str(func[2]))
        print("###SRC_START### " + str(var[1]))
        for sline in var[1]:
            sNum = int(sline) - 1
            fp = open(fileName, 'rt')
            for i, line in enumerate(fp):
                if i == sNum:
                    print(sNum+1, line[:-1].strip())
                    break
            fp.close()
        print("###SRC_END###")
        print("###LABEL[ " + str(var[2]) + " ]")
        print("##SNIPPET_END##\n")
    print("#FILE_END#\n")
    return bool(True)

def run():
    snippetCnt = slicing()
    print(snippetCnt)


### execution ###
if __name__=="__main__":
    #filename="/home/kevin/works/sard/dataset/SARD/SARD-1/62540/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_41.c"
    #_slicing(filename)
    #print(snippetList)
    
    run()
