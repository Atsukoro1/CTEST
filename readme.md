# Netscrape

Netscape is CLI that sniffs for incoming packets on specific wireless interface
and prints in in Human Readable format. Netscape will not work on Windows because
LibPCap library only works on GNU/Linux. Also this is my first tool made with C so it may contain some memory leaks and other problems.

## Installation

Use GNU-C-Compiler [GCC](https://gcc.gnu.org/) to compile the main.c file

1. Make sure all libraries are installed
```bash
# Ubuntu
sudo apt-get update -y
sudo apt-get install -y libpcap-dev

# Arch
# At Arch, devel is included in normal libpcap
sudo pacman -S libpcap
```

2. Compile program using GCC
```bash
# Ubuntu version
gcc main.c -o output -L/usr/include -lpcap && ./output
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.