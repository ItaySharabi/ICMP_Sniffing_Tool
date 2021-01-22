CC = gcc

FLAGS = -Wall -g
all: sniffer myping

sniffer: sniff.o
	$(CC) $(FLAGS) -o Sniffer sniff.o
sniff.o: sniff.c
	$(CC) $(FLAGS) -c sniff.c
myping: myping.o
	$(CC) $(FLAGS) -o myping myping.o
myping.o: myping.c
	$(CC) $(FLAGS) -c myping.c

clean:
	rm Sniffer myping *.o

.PHONY: clean