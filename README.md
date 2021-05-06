[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.4478131.svg)](https://doi.org/10.5281/zenodo.4478131)
# Automated Vulnerability Analysis System (AutoVAS)
![Graphical_Abstract](https://user-images.githubusercontent.com/48042609/107875662-8fea9580-6f04-11eb-8c4f-a4357b51128e.png)

## Abstract
<img width="898" alt="abstract" src="https://user-images.githubusercontent.com/48042609/107858579-47859600-6e78-11eb-945f-a5f9ef5c5d0a.png">

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

## Discovery of Vulnerabilities
As described in below table, we detect eleven vulnerabilities. Among them, seven vulnerabilities are already registerd in CVE and three vulnerabilities are not reported in NVD but they have been “silently” patched by the vendors when releasing newer version of the products. The other one vulnerability is received CVE ID (CVE-2019-15903).

***Known Vulnerabilities***
<img width="1056" alt="known_vul" src="https://user-images.githubusercontent.com/48042609/107858685-afd47780-6e78-11eb-81f7-6bafe7a24704.png">

***Unknown Vulnerabilities***
<img width="1059" alt="unknown_vul" src="https://user-images.githubusercontent.com/48042609/107858687-b531c200-6e78-11eb-9281-558696682595.png">

## Publications
```
Jeon, S. H., & Kim, H. K. (2021). AutoVAS: An Automated Vulnerability Analysis System with a Deep Learning Approach. Computers & Security, 102308.

@article{jeon2021autovas,
  title={AutoVAS: An Automated Vulnerability Analysis System with a Deep Learning Approach},
  author={Jeon, Sang Hoon and Kim, Huy Kang},
  journal={Computers \& Security},
  pages={102308},
  year={2021},
  publisher={Elsevier}
}
```

## About
This program is authored and maintained by **Sanghoon(Kevin) Jeon**.
> Email: kppw99@gmail.com

> GitHub[@kppw99](https://github.com/kppw99/autoVAS)
