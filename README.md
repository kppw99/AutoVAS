[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.4478131.svg)](https://doi.org/10.5281/zenodo.4478131)
# Automated Vulnerability Analysis System (AutoVAS)
![Graphical_Abstract](https://user-images.githubusercontent.com/48042609/107875662-8fea9580-6f04-11eb-8c4f-a4357b51128e.png)

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

## Publications
```
Jeon, S., & Kim, H. K. (2021). AutoVAS: An Automated Vulnerability Analysis System with a Deep Learning Approach. Computers & Security, 102308.

@article{jeon2021autovas,
  title={AutoVAS: An Automated Vulnerability Analysis System with a Deep Learning Approach},
  author={Jeon, Sanghoon and Kim, Huy Kang},
  journal={Computers & Security},
  pages={102308},
  year={2021},
  publisher={Elsevier}
}
```

## Notice
The uploaded snippet, which consists of the C language-based snippet, is part of a total snippet. In the NVD dataset, we applied some heuristic points as a slicing criterion such as arithmetic, array, etc., in addition to vulnerable APIs. Lastly, we only uploaded snippets after preprocessing without the program slicing module.

## About
This program is authored and maintained by **Sanghoon(Kevin) Jeon**.
> Email: kppw99@gmail.com

> GitHub[@kppw99](https://github.com/kppw99/autoVAS)
