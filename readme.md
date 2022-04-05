# Netscrape

Netscape is command line tool that sniffs for incoming packets on specific wireless interface
and prints them in Human Readable format. Netscrape will not work on Windows because
LibPCap library only works on GNU/Linux. Also this is my first tool made with C so it may contain some memory leaks and other problems.

## Compiling and running

Use GNU-C-Compiler [GCC](https://gcc.gnu.org/) or the makefile in root directory to compile Netscrape.

1. Make sure all libraries are installed
```bash
# Ubuntu
sudo apt-get update -y
sudo apt-get install -y libpcap-dev

# At Arch, devel is included in normal libpcap
sudo pacman -Syu
sudo pacman -S libpcap
```

2. Compile program using GCC
```bash
gcc main.c -o output -L/usr/include -lpcap && sudo ./output

or simply

make
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
