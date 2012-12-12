#ifndef _ASN1PARSER_H_INCLUDED
#define _ASN1PARSER_H_INCLUDED

#include<openssl/bn.h>
#include<string>

using namespace std;

#define ASN1_Universal 0x00
#define ASN1_Application 0x40
#define ASN1_Context_Specific 0x80
#define ASN1_Private 0xC0

#define ASN1_Primitive 0x00
#define ASN1_Constructed 0x20

#define ASN1_EOC 0x00
#define ASN1_Boolean 0x01
#define ASN1_Bit_string 0x03
#define ASN1_Integer 0x02
#define ASN1_Null 0x05
#define ASN1_OID 0x06
#define ASN1_Sequence 0x10

const string oid = "2A864886F70D010101"; // Encryption Object ID: 1.2.840.113549.1.1.1 (rsa encryption - PKCSv1.2)

string asn1_unpack(string, int *);

int asn1_public_parse(string, string *, string *);
string asn1_pub_pack(string, string, int);

int asn1_private_parse(string, string *, string *, string *, string *, string *, string *, string *, string *, int);
string asn1_private_pack(string, string, string, string, string, string, string, string, int);
string i2s(int);

#endif



