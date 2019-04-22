packets: packets.o
	gcc -Wall packets.o -o packets -L./ -lpcap

packets.o: packets.c
	gcc -c -g -Wall packets.c

clean:
	rm *.o packets
