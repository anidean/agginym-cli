keyutil: keyutil.cpp
	g++ -std=c++20 keyutil.cpp -Llibs -Irapidjson/include/ -Ifmt/include -l:libfmt.a -lsodium -o keyutil

default:
	keyutil
