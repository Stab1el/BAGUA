This is source code for ++Towards Automatic and Precise Heap Layout Manipulation for General-Purpose Programs++.  
## Introduction  

BAGUA aims to extract heap layout primitives from target programs, and achieve automatic heap manipulation by assembling the primitives.  Here we open the implementation of our core insight, which includes primitive capability modeling, ILP modeling, dealing with side effects, and primitive sorting.  

## Running Environment  

BAGUA is now implemented in `Unix` system, whose heap allocators have specific behaviours.   The recommneded running environment is 

``` 
Ubuntu 20.04 64 bit 
glibc 2.31 (or glibc 2.24) 
python 2.X 

```  

## Usage  

In this project, BAGUA takes primitives as input, and output the sorted primitive sequences.  

To run the project, you firstly need to dump the initial heap layout driven by PoC, and extract the heap primitives and the dependency.  
We give an example of CVE-2018-6789. To run the project, you could just run the script 

``` python2  hplayout_generator.py ```
