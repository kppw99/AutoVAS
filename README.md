# AutoVAS: an Automated Vulnerability Analysis System with Deep Learning Approach 
Due to the advances in automated hacking and analysis technologies in recent years, numerous software security vulnerabilities have been announced. Software vulnerabilities are increasing at a fast pace, whereas methods to analyze and cope with them depend on manual analyses, which involve a slow response. In recent years, studies concerning the prediction of vulnerabilities, or the detection of patterns of previous vulnerabilities have been conducted by applying deep learning algorithms in an automated vulnerability search based on source code.
 
However, existing methods target only some types of security vulnerabilities, or make limited use of source code to compile information, and few studies have been conducted on methods that represent source code in the embedding vector. Thus, this study proposes a deep learning-based automated vulnerability analysis system (AutoVAS) that uses a method to effectively represent source code in embedding vectors by using datasets from various projects in the National Vulnerability Database (NVD) and Software Assurance Reference Database (SARD).

The proposed technique achieved an False Positive Rate (FPR) of 1.88\, an False Negative Rate (FNR) of 3.62\%, and an F1-score of 96.11\%, and detected nine vulnerabilities by applying the technique to seven open-source projects. Six vulnerabilities were known Common Vulnerabilities and Exposures (CVE), and three of them were not registered in the NVD but were silently patched by the vendor in the next version of their software. One of nine vulnerabilities was registered in the CVE.
## Prerequisite
- [Python3](https://www.python.org/downloads/), [Java runtime 8](http://openjdk.java.net/install/), [sbt (Scala build tool)](https://www.scala-sbt.org/)
- [Joern](https://github.com/ShiftLeftSecurity/joern) ([documents](https://joern.io/docs/))
- cpgclientlib library for using cpg ($ pip install cpgclientlib)
- HTMLTestRunner for making test reports ($ pip install HTMLTestRunner)
- coverage for checking the test coverage ($ pip install coverage)
## Requirements
- Backward / Forward Slicing
- Including Data Flow (DAF) / Data & Control Flow (CDF)
- Slicing Unit: Function / Interprocedure
- Program Point: API Function List (Need to define more detail)
## To do list (Temporal Section)
- Create Test Case for each function and user scenarios.
- Apply Unittest Framework.
- Develop slicing tool to pass test cases.
