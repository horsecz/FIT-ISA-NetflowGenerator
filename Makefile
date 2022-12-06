CC=g++ -std=c++17
CFLAGS=-g -pedantic -Wall -Werror -Wextra
NAME=flow
LOGIN=xhorky32

all: main

isa_bitset.o: isa_bitset.cpp isa_bitset.hpp isa.hpp
	$(CC) $(CFLAGS) -c $<

isa_collector.o: isa_collector.cpp isa_collector.hpp isa.hpp
	$(CC) $(CFLAGS) -c $<

isa_flow.o: isa_flow.cpp isa_flow.hpp isa_bitset.hpp isa.hpp
	$(CC) $(CFLAGS) -c $<

isa_argparse.o: isa_argparse.cpp isa_argparse.hpp isa_classes.hpp isa_collector.hpp isa.hpp
	$(CC) $(CFLAGS) -c $<

isa_flowexport.o: isa_flowexport.cpp isa_flowexport.hpp
	$(CC) $(CFLAGS) -c $<

isa_classes.o: isa_classes.cpp isa_classes.hpp
	$(CC) $(CFLAGS) -c $<

isa_utility.o: isa_utility.cpp isa_utility.hpp
	$(CC) $(CFLAGS) -c $<

main.o: main.cpp isa.hpp
	$(CC) $(CFLAGS) -c $<

main: isa_utility.o isa_classes.o isa_flowexport.o isa_argparse.o main.o isa_bitset.o isa_collector.o isa_flow.o
	$(CC) $(CFLAGS) isa_utility.o isa_classes.o isa_flowexport.o isa_argparse.o main.o isa_bitset.o isa_collector.o isa_flow.o -lpcap -o $(NAME)

clean:
	rm -rf *.o $(NAME)

remake: clean main

pack: clean
	rm -rf $(LOGIN).tar
	tar -cf $(LOGIN).tar *

manpage:
	man -l $(NAME).1