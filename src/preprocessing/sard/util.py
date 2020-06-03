#!/usr/bin/env python3

### import library ###
import sys, os, time
from tqdm import tqdm
from colorama import Fore

# When you change directory, please check *_DIR variables.
SARD_DIR = '/../../../dataset/source/SARD/'
RESOURCE_DIR = '/../../../resource/'
DATASET_DIR = '/../../../dataset/'

### Global Variable ###
stdout = 0
parseDic = {
    "startFile": "#FILE_START#",
    "endFile": "#FILE_END#",
    "snippetStart": "##SNIPPET_START##",
    "snippetEnd": "##SNIPPET_END##",
    "varToken": "###VAR",
    "vsToken": "###VS",
    "funcToken": "###FUNCINFO",
    "labelToken": "###LABEL",
    "startSRC": "###SRC_START###",
    "endSRC": "###SRC_END###"
}
bar_flag = 0
bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Fore.RESET)


### Define API Functions ###
def setCaptureLog(fileName):
    global stdout
    stdout = sys.stdout
    sys.stdout = open(fileName, 'wt')

def clearCaptureLog():
    global stdout
    sys.stdout.close()
    sys.stdout = stdout

# We DO NOT use this function any more. (Please use tqdm library)
def printProgress(iter, total, pre="Progress", suf="Complete",
        decimals=1, barLength=40):
    formatStr = "{0:." + str(decimals) + "f}"
    percent = formatStr.format(100 * (iter / float(total)))
    fileLength = int(round(barLength * iter / float(total)))
    bar = "#" * fileLength + "-" * (barLength - fileLength)
    sys.stdout.write("\r%s |%s| %s%s %s" % (pre, bar, percent, "%", suf)),
    if iter == total:
        sys.stdout.write("\n")
    sys.stdout.flush()

def printList(inList, title="Print List"):
    print("[*]", title)
    for item in inList:
        print(item)

def clearFile(fileName):
    if os.path.isfile(fileName) == False:
        print("Please check the fileName:", fileName)
        return False
    os.system("rm -rf " + fileName)
    os.system("touch " + fileName)
    return True

def getDatasetDir():
    return os.getcwd() + DATASET_DIR

def getSARDDir():
    return os.getcwd() + SARD_DIR

def getDirListName():
    fileName = _getResourceDir() + 'sard_dirList.txt'
    if not os.path.isfile(fileName):
        _mknod(fileName)
    return fileName

def getTargetListName():
    fileName = _getResourceDir() + 'sard_targetList.txt'
    if not os.path.isfile(fileName):
        _mknod(fileName)
    return fileName

def getErrorFileName():
    fileName = _getResourceDir() + 'sard_error.txt'
    if not os.path.isfile(fileName):
        _mknod(fileName)
    return fileName

def getSnippetFileName():
    fileName = _getResourceDir() + 'sard_snippet.txt'
    if not os.path.isfile(fileName):
        _mknod(fileName)
    return fileName

def getAPIListFileName():
    fileName = _getResourceDir() + 'apiList.txt'
    if not os.path.isfile(fileName):
        _mknod(fileName)
    return fileName

def getResultFileName():
    fileName = _getResourceDir() + 'sard_result.txt'
    if not os.path.isfile(fileName):
        _mknod(fileName)
    return fileName

def getTokenFileName():
    fileName = _getResourceDir() + 'sard_tokens.txt'
    if not os.path.isfile(fileName):
        _mknod(fileName)
    return fileName

def getDirCnt():
    dirName = getDirListName()
    if not os.path.isfile(dirName):
        return 0
    fp = open(dirName)
    dirs = fp.readlines()
    fp.close()
    return len(dirs)

def getTargetCnt():
    targetFile = getTargetListName()
    if not os.path.isfile(targetFile):
    	return 0
    fp = open(targetFile)
    files = fp.readlines()
    fp.close()
    return len(files)

def makeSARDList(sardDir=None, dirFile=None, targetFile=None):
	global bar_flag
	retVal = True
	bar_flag = 0
	if sardDir is None:
		sardDir = getSARDDir()
	if dirFile is None:
		dirFile = getDirListName()
	if targetFile is None:
		targetFile = getTargetListName()
	if not os.path.isfile(dirFile) or getDirCnt() == 0:
		print("[*] Make SARD Directory File")
		clearFile(dirFile)
		retVal = _makeDirList(sardDir, dirFile)
	if not os.path.isfile(targetFile) or getTargetCnt() == 0:
		print("[*] Make Target File")
		clearFile(targetFile)
		retVal = _makeTargetList(sardDir, targetFile)
	bar_flag = 0
	return retVal

def initSARDList():
    print("[*] Init SARD List")
    clearFile(getDirListName())
    clearFile(getTargetListName())

def initSnippetList():
    print("[*] Init Snippet List")
    clearFile(getSnippetFileName())
    clearFile(getErrorFileName())

def getTargetList():
    targetList = list()
    targetFile = getTargetListName()
    if not os.path.isfile(targetFile) or getTargetCnt() == 0:
        print("Please execution makeSARDList function!")
        return targetList
    fp = open(targetFile, 'r')
    files = fp.readlines()
    for file in files:
        targetList.append(file[:-1])
    fp.close()
    return sorted(targetList)

### Define Local Functions ###
def _mknod(filename):
    with open(filename, 'w') as file:
        pass

def _getResourceDir():
    dirName = os.getcwd() + RESOURCE_DIR
    if not os.path.isdir(dirName):
        os.makedirs(dirName)
    return dirName

def _makeDirList(dirName, listName):
    global bar_flag
    if dirName == "" or os.path.isdir(dirName) == False:
        print("Please check the root dirName!!!", dirName)
        return False
    dirs = os.listdir(dirName)
    if bar_flag == 0:
        bar_flag = 1
        for dir in tqdm(dirs, unit_scale=True, bar_format=bar_format):
            fullName = os.path.join(dirName, dir)
            if os.path.isdir(fullName): #directory
                _makeDirList(fullName, listName)
            else: #file
                ext = os.path.splitext(fullName)[-1]
                if ext != ".c":
                    continue
                else:
                    f = open(listName, mode='at')
                    f.write(dirName + '\n')
                    f.close()
                    break
    else:
        for dir in dirs:
            fullName = os.path.join(dirName, dir)
            if os.path.isdir(fullName): #directory
                _makeDirList(fullName, listName)
            else: #file
                ext = os.path.splitext(fullName)[-1]
                if ext != ".c":
                    continue
                else:
                    f = open(listName, mode='at')
                    f.write(dirName + '\n')
                    f.close()
                    break
    return True

def _findTargetFiles(dirName, targetName):
    if not os.path.isdir(dirName):
    	print("Please check the dirName!!!", dirName)
    	return False
    files = os.listdir(dirName)
    fp = open(targetName, mode='at')
    for fileName in files:
        if fileName.find("CWE") >= 0:
            fullName = os.path.join(dirName, fileName)
            ext = os.path.splitext(fullName)[-1]
            if ext == ".c":
                fp.write(fullName + "\n")
    fp.close()
    return True

def _makeTargetList(dirName, targetName):
    dirList = getDirListName()
    if not os.path.isfile(dirList):
    	print("Please Make DirList file in advance!")
    	return False
    fp = open(dirList)
    dirs = fp.readlines()
    for dir in tqdm(dirs, unit_scale=True, bar_format=bar_format):
        _findTargetFiles(dir[:-1], targetName)
    fp.close()
    return True


### execution ###
if __name__=="__main__":
    initSARDList()
    makeSARDList()
