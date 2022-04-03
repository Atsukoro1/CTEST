all: create_folder compile_dependencies compile_tool run

create_folder:
	mkdir -p ./build

compile_dependencies:
	gcc -c main.c capture.c interfaces.c && mv *.o ./build

compile_tool:
	gcc ./build/capture.o ./build/interfaces.o ./build/main.o -L/usr/include -lpcap -o netscrape

run:
	mv ./netscrape ./build/ && chmod +x ./build/netscrape && sudo ./build/netscrape 