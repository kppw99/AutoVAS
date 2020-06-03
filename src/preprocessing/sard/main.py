#!/usr/bin/env python3


# MUST execute this function at the google colab.
def colabMain():
    # mount for google drive
    from google.colab import drive
    drive.mount('/content/gdrive/')
    
    # set python path
    import sys
    sys.path.append('/content/gdrive/My Drive/autoVAS')
    
    # import parsing module (custom python file)
    from parsing import parsing
    
    # make snippet, result, and apiList filename
    file_path = '/content/gdrive/My Drive/autoVAS/'
    snippet_prefix = 'snippet/sard_snippet'
    result_prefix = 'result/sard_result'
    postfix = ['_0001_1000.txt', '_1001_2000.txt', '_2001_3000.txt',
               '_3001_4000.txt', '_4001_5000.txt', '_5001_6000.txt',
               '_6001_7000.txt', '_7001_8000.txt', '_8001_9283.txt']
    
    apiList = file_path + 'resource/apiList.txt'
    
    snippets = list()
    results = list()
    for item in postfix:
        snippets.append(file_path+snippet_prefix+item)
        results.append(file_path+result_prefix+item)
    
    # do parsing (set cnt)
    s_num = 0
    e_num = 1
    for snippet, result in zip(snippets[s_num:e_num], results[s_num:e_num]):
        print('[*] Start to do parsing using below files')
        print('snippet:', snippet)
        print('result:', result)
        parsing(snippetFile=snippet, apiListFile=apiList, resultFile=result)


def sardMain():
    import util as util
    from parsing import parsing
    from slicing import slicing
    from util import initSARDList, initSnippetList
    from util import makeSARDList, getTargetList

    # 1.Create dirList.txt, targetList.txt (based on SARD directory)
    # If there is no change of SARD dataset, do not need to do step 1.
    # Enable to execute at any environment
    sardDir = util.getSARDDir()
    dirFile = util.getDirListName()
    targetFile = util.getTargetListName()
    initSARDList()
    makeSARDList(sardDir, dirFile, targetFile)

    # 2.Create snippet.txt and error.txt (using by program slicing)
    # Please check output files of step1 before doing step 2.
    # If there is already snippet.txt, do not need to do step 2.
    # Enable to execute at only ubuntu 14.02 installed llvm-slicing
    snippetFile = util.getSnippetFileName()
    initSnippetList()
    slicing(snippetFile)

    # 3.Create result.txt that is token file as an input of embedding.
    # Please check output files of step2 and apiList.txt before doing step 3.
    # This step takes a very long time, recommends splitting the 'snippet.txt'.
    # Enable to execute at any environment
    apiListFile = util.getAPIListFileName()
    resultFile = util.getResultFileName()
    parsing(snippetFile=snippetFile, apiListFile=apiListFile,
            resultFile=resultFile)


if __name__=="__main__":
    #sardMain()
    from util import getAPIListFileName, getDatasetDir
    from parsing import parsing
    apiListFile = getAPIListFileName()
    datasetPath = getDatasetDir()
    snippetFile = datasetPath + 'snippet/sard_snippet_8001_9283.txt'
    resultFile = datasetPath + 'token/sard_result_8001_9283.txt'
    parsing(snippetFile=snippetFile, apiListFile=apiListFile,
            resultFile=resultFile)
