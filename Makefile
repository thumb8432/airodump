all: airodump

airodump: airodump.cpp
	g++ -o airodump airodump.cpp -lpcap -lglog -W -Wall

clean:
	rm airodump
