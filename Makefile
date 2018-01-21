all: airodump

airodump: airodump.cpp ieee80211.h
	g++ -o airodump airodump.cpp -lpcap -lglog -lpthread -std=c++11 -W -Wall

clean:
	rm airodump
