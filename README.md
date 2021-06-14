# pyELFer
### A python tool to analyze and exploiting ELF Binaries
This tool first runs some basic enumerations like using strings to group the printable characters in binary which includes some important information like User defined functions , Predefined functions ,Sections and Compiler generated functions,name of the source code compiled binary sysinfo and compiler info into /tmp/pyELFer/strings_for_(file_name).txt..

Then proceeds to perform a ropchain 

Usage:
```
git clone https://github.com/vital-information-resource-under-siege/pyELFer.git
cd pyELFer
sh setup.sh
python3 pyELFer.py -f (location of binary file name)
```

#### Help:

```
python3 pyELFer.py -h 
```
