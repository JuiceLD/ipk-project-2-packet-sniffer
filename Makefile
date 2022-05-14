all: sniffer

sniffer: ipk-sniffer.c
	gcc -Wall -Wextra ipk-sniffer.c -o ipk-sniffer -lpca
