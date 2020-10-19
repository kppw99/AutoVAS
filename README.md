# AutoVAS: an Automated Vulnerability Analysis System with Deep Learning Approach 
Due to the advances in automated hacking and analysis technologies in recent years, numerous software security vulnerabilities have been announced. Software vulnerabilities are increasing at a fast pace, whereas methods to analyze and cope with them depend on manual analyses, which involve a slow response. In recent years, studies concerning the prediction of vulnerabilities, or the detection of patterns of previous vulnerabilities have been conducted by applying deep learning algorithms in an automated vulnerability search based on source code.
 
However, existing methods target only some types of security vulnerabilities, or make limited use of source code to compile information, and few studies have been conducted on methods that represent source code in the embedding vector. Thus, this study proposes a deep learning-based automated vulnerability analysis system (AutoVAS) that uses a method to effectively represent source code in embedding vectors by using datasets from various projects in the National Vulnerability Database (NVD) and Software Assurance Reference Database (SARD).

The proposed technique achieved an False Positive Rate (FPR) of 1.88\, an False Negative Rate (FNR) of 3.62\%, and an F1-score of 96.11\%, and detected nine vulnerabilities by applying the technique to seven open-source projects. Six vulnerabilities were known Common Vulnerabilities and Exposures (CVE), and three of them were not registered in the NVD but were silently patched by the vendor in the next version of their software. One of nine vulnerabilities was registered in the CVE.

## Prerequisite
***For NVD Dataset***
- [Python3](https://www.python.org/downloads/), [Java runtime 8](http://openjdk.java.net/install/), [sbt (Scala build tool)](https://www.scala-sbt.org/)
- [Joern](https://github.com/ShiftLeftSecurity/joern) ([documents](https://joern.io/docs/))
- cpgclientlib library for using cpg ($ pip install cpgclientlib)

***For SARD Dataset***
- [LLVM-Slicing](https://github.com/zhangyz/llvm-slicing)

***For Evaluation***
- HTMLTestRunner for making test reports ($ pip install HTMLTestRunner)
- coverage for checking the test coverage ($ pip install coverage)

## Description of directory
- ***Dataset***: Original source code of dataset, snippet files, tokenizing file  
- ***Resource***: Slicing criterion file
- ***src***: Main source code of AutoVAS. The src direction has model and preprocessing folder.
- ***tool***: Utility files for AutoVAS such as joern, llvm-slicing

## Vulnerabilities
As described in below table, we detect nine vulnerabilities. Among them, six vulnerabilities are already published in NVD and three vulnerabilities are not reported in NVD but they have been “silently” patched by the vendors when releasing newer version of the products. The other one vulnerability is received CVE ID (CVE-2019-15903).

|Project|Val. Type|CVE|Version or Commit ID|
|:---:|:---|:---|:---|
|c-ares|heap buffer overflow|(known) CVE-2016-5180|v1.11.0|
|Thunderbird|stack buffer overflow|(known) CVE-2015-4511|v38.0.1|
|Xen|integer overflow|(known) CVE-2016-9104|v4.6.0|
|Xen|infinite loop|(known) CVE-2016-4453|v4.7.4|
|cJSON|NULL dereference|(known) CVE-2019-1010239|v1.7.8|
|boringssl|heap use after free|silent-patch|894a47df2423f0d2b6be57e6d90f2bea88213382|
|mpc|stack buffer overflow|silent-patch|b31e02e427f55d4ce69c33ed9936a1b396628440|
|mpc|heap buffer overflow|silent-patch|b31e02e427f55d4ce69c33ed9936a1b396628440|
|expat|heap buffer overflow|(unknown) CVE-2019-15903|v2.2.8|