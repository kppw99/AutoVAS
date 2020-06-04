#!/usr/bin/env python3

import os, json

from tqdm import tqdm
from pprint import pprint
from util import validFile, getNVDDir, getNVDTargetList, _getNVDResourceDir
from util import getTargetListName, getCpgParsingList
from cpgclient.CpgClient import CpgClient


server='127.0.0.1'
port=8080
client=CpgClient(server, port)


def _query(query):
    return client.query(query)

def _set2list(setData):
    retVal = list()
    tempStr = 'set('
    tempIdx = setData.find(tempStr)
    tempList = setData[tempIdx+4:-1].split(',')
    for item in tempList:
        retVal.append(item.replace(' ', ''))
    return retVal

def parse(filename):
    if not validFile(filename):
        print("Please check the filename:", filename)
        return False
    client.create_cpg(filename)
    return True

def getMethodList():
    retVal = _set2list(_query('cpg.method.name.toSet'))
    return [x for x in retVal if not '<operator>' in x]

def getVarList(funcList):
    retVal = list()
    prefix = 'cpg.method.name(\"'
    for funcName in funcList:
        paramQuery = prefix + funcName + '\").parameter.name.toSet'
        localQuery = prefix + funcName + '\").local.name.toSet'
        idenQuery  = 'cpg.identifier.name.toSet'
        paramList = _set2list(_query(paramQuery))
        localList = _set2list(_query(localQuery))
        idenList  = _set2list(_query(idenQuery))
        retVal.extend(list(set(paramList + localList + idenList)))
    retVal = [x.replace('(','') for x in retVal]
    retVal = [x.replace(')','') for x in retVal]
    return list(set(retVal))

def getTargetFuncName(methodList):
    retVal = list()
    for method in methodList:
        if method.find('CVE') >= 0:
            retVal.append(method)
    return retVal

def nvdParsing(targetList, result):
    retVal = dict()
    for target in tqdm(targetList):
        temp = dict()
        parse(target)
        methodList = getMethodList()
        targetFunc = getTargetFuncName(methodList)
        varList = getVarList(targetFunc)
        filename = target.split('/')[-1]
        temp['target'] = targetFunc
        temp['methods'] = methodList
        temp['vars'] = varList
        retVal[filename] = temp
    json.dump(retVal, open(result, 'w'))
    return retVal

def run():
    targetList = getNVDTargetList()
    outputs = getCpgParsingList()
    nvdParsing(targetList[1400:], outputs[-1])


if __name__=='__main__':
    run()

