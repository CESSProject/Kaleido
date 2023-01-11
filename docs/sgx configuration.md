# Sgx Configuration

## Hardware Requirements

* The CPU used must support SGX (SoftwareGuardExtensions)
* Instance minimum memory:32G
* Minimum number of CPU:8

## Software Requirements

* The BIOS used must support Intel SGX
* There must be an option to enable Intel SGX in BIOS: sgx enable has three options (enable, disable, software control), please select enable, refer to your machine manufacturer's BIOS guide to enable SGX function
* Ubuntu kernel must be 5.4~5.6, recommended version kernel 5.4
* Ubuntu version recommended 18.04, 20.04

## Configuration Requirements

* Turn on 'Intel SGX Enable' in BIOS, select enable
* Set 'Intel Memory Size' in BIOS, the maximum is 37.5% of the machine memory, and the minimum is 5G



## Command Support

```shell
##Query the CPU model command of Ubuntu
cat /proc/cpuinfo | grep 'model name' |uniq

##Query the Ubuntu kernel version
hostnamectl |grep Kernel

##Check if this machine supports SGX
cpuid | grep -i sgx
```

View CPU models that support sgx:https://ark.intel.com/content/www/us/en/ark/search/featurefilter.html?productType=873

The search method is as follows, the CPU under this category supports SGX:

![image](https://user-images.githubusercontent.com/69138672/211731913-564c696e-6a5d-4006-aacc-b7b2bf781bd7.png)