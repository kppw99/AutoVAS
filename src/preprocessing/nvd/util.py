#!/usr/bin/env python3

import os
from tqdm import tqdm


# When you change directory, please check *_DIR variables.
NVD_DIR = '/../../../dataset/source/NVD/'
RESOURCE_DIR = '/../../../resource/'
DATASET_DIR = '/../../../dataset/'

_SEP = '------------------------------\n'


def _mknod(filename):
    with open(filename, 'w') as file:
        pass

def _getNVDResourceDir():
    dirName = os.getcwd() + RESOURCE_DIR
    if not os.path.isdir(dirName):
        os.makedirs(dirName)
    return dirName

def getDatasetDir():
    return os.getcwd() + DATASET_DIR

def getNVDDir():
    return os.getcwd() + NVD_DIR

def getAPIListFileName():
    fileName = _getNVDResourceDir() + 'apiList.txt'
    if not os.path.isfile(fileName):
        _mknod(fileName)
    return fileName

def getNVDResultFileName():
    filename = getDatasetDir() + 'token/nvd_result.txt'
    if not os.path.isfile(filename):
        _mknod(filename)
    return filename

def validFile(filename):
    if not os.path.isfile(filename):
        return False
    filename = filename.split('/')[-1]
    _, ext = os.path.splitext(filename)
    if ext == '.cpp' or ext == '.cc' or ext == '.c' or ext == '.h':
        return True
    else:
        return False

def getNVDTargetList(nvdDir=None):
    path = getNVDDir()
    targetList = list()
    filename = getTargetListName()
    with open(filename, 'r') as f:
        targets = f.readlines()
        for target in targets:
            fullname = path + target[:-1]
            targetList.append(fullname)
            if not os.path.isfile(fullname):
                print(fullname)
    return targetList

def getTargetListName():
    filename = _getNVDResourceDir() + 'nvd_targetList.txt'
    if not os.path.isfile(filename):
        _mknod(filename)
    return filename

def getSnippetFileName():
    filename = getDatasetDir() + 'snippet/nvd_snippet_all.txt'
    if not os.path.isfile(filename):
        _mknod(filename)
    return filename

def makeNVDList():
    targetList = list()
    inputFiles = getSlicingList()
    for filename in inputFiles:
        with open(filename, 'r') as f:
            snippetFlag = 0
            lines = f.readlines()
            for line in tqdm(lines):
                lineList = line.split()
                if snippetFlag == 0:
                    filepath = lineList[1]
                    filepath = filepath.split('/')
                    targetList.append(filepath[1])
                    snippetFlag = 1
                    continue
                if line == _SEP:
                    snippetFlag = 0
    targetList = list(set(targetList))
    targetList = sorted(targetList)
    target_file = getTargetListName()
    with open(target_file, 'w') as f:
        for target in targetList:
            f.writelines(target+"\n")

def getSlicingList():
    retVal = list()
    slicing_files = [
        'snippet/nvd_slicing_pointer.txt',
        'snippet/nvd_slicing_api.txt',
        'snippet/nvd_slicing_arithmetic.txt',
        'snippet/nvd_slicing_array.txt'
    ]
    for slicing_file in slicing_files:
        retVal.append(getDatasetDir() + slicing_file)
    return retVal

def getCpgParsingList():
    retVal = list()
    cpgParsing_files = [
        'snippet/nvd_parsing_000_100.json',
        'snippet/nvd_parsing_100_200.json',
        'snippet/nvd_parsing_200_300.json',
        'snippet/nvd_parsing_300_400.json',
        'snippet/nvd_parsing_400_500.json',
        'snippet/nvd_parsing_500_600.json',
        'snippet/nvd_parsing_600_700.json',
        'snippet/nvd_parsing_700_800.json',
        'snippet/nvd_parsing_800_900.json',
        'snippet/nvd_parsing_900_1000.json',
        'snippet/nvd_parsing_1000_1100.json',
        'snippet/nvd_parsing_1100_1200.json',
        'snippet/nvd_parsing_1200_1300.json',
        'snippet/nvd_parsing_1300_1400.json',
        'snippet/nvd_parsing_1400_.json'
    ]
    for filename in cpgParsing_files:
        retVal.append(getDatasetDir() + filename)
    return retVal

def mergeDict(dictList):
    retVal = dict()
    for dictionary in dictList:
        retVal.update(dictionary)
    return retVal


if __name__=='__main__':
    #makeNVDList()
    print(getTargetListName())
    #filename = 'CVE_2005_3359_PATCHED___sock_create.c'
    #fullname = getNVDDir() + filename
    #print(filename)
    #print(fullname)
    #print(validFile(fullname))
    #targetList = getNVDTargetList()
    #for target in targetList:
    #    print(target)
