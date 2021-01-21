CC = gcc

FLAGS = -Wall -g
all: sniffer icmp

sniffer: sniff.o
	$(CC) $(FLAGS) -o Sniffer sniff.o
sniff.o: sniff.c
	$(CC) $(FLAGS) -c sniff.c
icmp: icmp.o
	$(CC) $(FLAGS) -o icmp icmp.o
icmp.o: icmp.c
	$(CC) $(FLAGS) -c icmp.c

clean:
	rm Sniffer icmp *.o

.PHONY: clean