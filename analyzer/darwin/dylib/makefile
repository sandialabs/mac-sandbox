all:
	gcc -fno-common -O0 -g -c cuckoohooks.c -arch i386
	gcc -dynamiclib -o cuckoohooks_32.dylib cuckoohooks.o -arch i386
	gcc -fno-common -O0 -g -c cuckoohooks.c -arch x86_64
	gcc -dynamiclib -o cuckoohooks_64.dylib cuckoohooks.o -arch x86_64
	lipo -create cuckoohooks_32.dylib cuckoohooks_64.dylib -output cuckoohooks.dylib
