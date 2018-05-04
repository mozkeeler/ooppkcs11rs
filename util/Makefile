CXX=clang++
CXXFLAGS=-I/usr/include/nss3 -I/usr/include/nspr4 -Wall -g -std=c++11
LDFLAGS=-lnss3 -lnspr4

test: test.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o test test.cpp

clean:
	rm -f test cert8.db key3.db secmod.db
