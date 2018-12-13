PHONY: clean all

all:
	make -C code 
	make -C test

clean:
	make clean -C code
	make clean -C test
