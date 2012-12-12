#ifndef _CERT_H_INCLUDED
#define _CERT_H_INCLUDED

#include<string>
#include<openssl/bn.h>

using namespace std;

const string sha_oid = "2A864886F70D010105";
const string country_oid = "550406";
const string state_oid = "550408";
const string city_oid = "550407";
const string org_oid = "55040A";
const string email_oid = "2A864886F70D010901";
const string rsa_oid = "2A864886F70D010101";
const string basic_constraint_oid = "551D13";
const string auth_key_id_oid = "551D23";
const string sub_key_oid = "551D0E";
const string cert_file_header = "-----BEGIN CERTIFICATE-----";
const string cert_file_footer = "-----END CERTIFICATE-----";
const string cert_priv_header = "-----BEGIN PRIVATE KEY-----";
const string cert_priv_footer = "-----END PRIVATE KEY-----";

string sha_hash(string);
string ascii_str(string);
string get_time(int);
string user_data(string, string, string, string, string);
string cert_asn1_pack(string *, string, string, string, string, string, int);
int cert_asn1_parse(string, string *, string *, string *, string *, string *, string *, string *, string *);
string cert_asn1_private_pack(string, string, string, string, string, string, string, string);
int private_encrypt_data(string, string, string);
int public_decrypt_data(string, string);
int cert_gen(string, int);

#endif
