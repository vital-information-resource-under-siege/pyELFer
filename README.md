# pyELFer
### A python tool to analyze and exploiting ELF Binaries
This tool first runs some basic enumerations like using strings to group the printable characters in binary which includes some important information like User defined functions , Predefined functions ,Sections and Compiler generated functions,name of the source code compiled binary sysinfo and compiler info into /tmp/pyELFer/strings_for_(file_name).txt..

Then proceeds to perform a ret2libc attack or ret2csu->ret2libc attack on binary both locally and remotely 

#### Usage:
```
git clone https://github.com/vital-information-resource-under-siege/pyELFer.git
cd pyELFer
sh setup.sh
python3 pyELFer.py -f (location of binary file name)
```

#### This tool does not work in the presence of mitigations like Position Independent executable and Stack canary ..And also works only on dynamically linked and non-stripped binaries.

#### Demo Video Link

[Demo working of the project](https://drive.google.com/file/d/1f60rCWNb7hfEfVbKVyMDi45ATOAlL5pt/view?usp=sharing)
The first input asked by the binary after specifying the binary in arguements and running the file is "Any extra input need to pass to point to the vulnerable buffer" if the binary straight away asks input to the vulnerable buffer do not give anythng and press enter if any other input or step needed to pass to point to the vulnerable buffer give that input here ..If any newlines occurs in the input ..Example if you want to give a option number(let's take 3 here) and newline to step to the vulnerable buffer give like this..

```
Any input need to pass to point to the vulnerable buffer:3newline
```

The tool replaces newline with '\n'

And then it asks for the offset(number) to reach the ret address which is number of characters needed  before to modify the ret address..

```
Enter the offset to reach ret address:40
```

After giving this if the offsets are correct seems correct shell will be spawned and asks if there is a remote server running this binary

And finally after closing the spawned shell ..It asks whether the shell has been spawned or not ..

```
Did shell popped 1 for yes 2 for no:
```

```
Do u have a remote server that run this binary that is open to exploit 1 for yes and with system libc file in hand and 2 for yes but no libc in hand and any other number for just local testing:
```

1 if there is a remote server running this binary and you have the libc file in your local system that is running in the binary and 2 if there is a remote server running this binary but you are not provided with a libc file and finally any other number if the binary does not a present on a remote server..


### Option 1:

The server asks for the remote server IP

```
Give me the Remote server IP:
```
And then it asks for remote server port 

```
Give me the Remote server's port:
```
And then asks for the location of libc file

```
Enter the location of server's libc file:
```

And then it tries upto 4 times to spawn a shell.. This is because in ubuntu 18.04 or later there is a movaps instruction issue.The first time it tries without ret gadgets and then the next 3 times it uses ret gadget to spawn a shell. If the shell does not spawn between these times..It asks whether shell has been spawned please gve no for the pyELFer to try the another time to try and spawn the shell..

```
Did Shell popped 1 for yes 2 for no:
```

#### Option 2:

The server asks for the remote server IP

```
Give me the Remote server IP:
```
And then it asks for remote server port 

```
Give me the Remote server's port:
```
And then after performing a libc leak it asks which libc version to use for the remote exploit 

```
Enter the index of libc you want to ensure for the exploitation process:
```

And then it tries upto 4 times to spawn a shell.. This is because in ubuntu 18.04 or later there is a movaps instruction issue.The first time it tries without ret gadgets and then the next 3 times it uses ret gadget to spawn a shell. If the shell does not spawn between these times..It asks whether shell has been spawned please gve no for the pyELFer to try the another time to try and spawn the shell..

```
Did Shell popped 1 for yes 2 for no:
```

#### Option other than 1 and 2:

It ends the program saying ..

```
Only local process exploit!!!
```

#### Help:

```
python3 pyELFer.py -h 
```

![help](https://github.com/vital-information-resource-under-siege/pyELFer/blob/main/images/pyELFer01.png)



