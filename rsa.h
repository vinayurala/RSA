#ifndef _RSA_H_INCLUDED
#define _RSA_H_INCLUDED

#include<string>
#include<openssl/bn.h>

using namespace std;

const string priv_file_header = "-----BEGIN RSA PRIVATE KEY-----";
const string priv_file_footer = "-----END RSA PRIVATE KEY-----";
const string pub_file_header = "-----BEGIN PUBLIC KEY-----";
const string pub_file_footer = "-----END PUBLIC KEY-----";

string* keygen(int, string);
void gen_pubkey(string, string);
string i2osp(BIGNUM *, int);
BIGNUM * os2ip(string, int);
int encrypt_data(string, string, string);
int decrypt_data(string, string, string);

#endif
