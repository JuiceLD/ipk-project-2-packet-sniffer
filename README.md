Autor: Adam Bazel, xbazel00@stud.fit.vutbr.cz
Projekt: IPK Projekt 2, varianta ZETA
Datum: 25. 4. 2021

Informace:
    Síťový analyzátor, který filtruje, zachytává a vypisuje datový obsah paket.

Spuštění:
	sudo ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p --port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
    
Příklady:
    sudo ./ipk-sniffer -i enp0s3 -n 5
    sudo ./ipk-sniffer -i enp0s3 --udp --tcp
    sudo ./ipk-sniffer -i enp0s3 -p 80
    sudo ./ipk-sniffer -i enp0s3 --arp
    sudo ./ipk-sniffer -i enp0s3 -p 80 --tcp --udp --icmp --arp -n 3

Odevzdané soubory:
    packet_sniffer.c, Makefile, manual.pdf, README.md
    
Omezení:
    V projektu nebyla implementována podpora paketu internetového protokolu verze 6 (IPv6).
