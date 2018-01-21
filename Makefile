all: airodump

airodump: airodump.cpp ieee80211.h
	g++ -o airodump airodump.cpp -lpcap -lglog -W -Wall

clean:
	rm airodump
