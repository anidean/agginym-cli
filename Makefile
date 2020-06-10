keyutil: keyutil.cpp
	g++ -std=c++20 keyutil.cpp -Llibs -Iincludes/ -l:libfmt.a -lsodium -o keyutil

default:
	keyutil
