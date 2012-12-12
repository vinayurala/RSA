# Makefile for RSA
CC = g++

CFLAGS = -lcrypto -lssl -g

myrsa: 
	 $(CC) $(CFLAGS) asn1_parser.cpp base64.cpp cert.cpp invoker.cpp rsa.cpp -o myrsa

clean:
	 rm -f myrsa