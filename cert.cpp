/* Contains modules for certificate creation, signing and verification of data. Most of the values for ASN.1 structure
   are hard-coded, as they do not change between various certificates, atleast for this project */

#include<iostream>
#include<string>
#include<sstream>
#include<fstream>
#include<ctime>
#include<cstring>
#include<iomanip>
#include<openssl/sha.h>
#include<openssl/bn.h>
#include "rsa.h"
#include "asn1_parser.h"
#include "base64.h"
#include "cert.h"

using namespace std;

/* Function to compute the SHA hash which is stored in the ceritifcate file */
string sha_hash(string msg)
{
  char *msg_char = new char[msg.length() + 1];
  int i = 0;
  unsigned char hash_char[SHA_DIGEST_LENGTH];
  string hash; 
  SHA_CTX sha256;
  ostringstream o;

  for(i = 0; i < msg.length(); i++)
    msg_char[i] = msg[i];

  SHA1_Init(&sha256);
  SHA1_Update(&sha256, msg_char, msg.length());
  SHA1_Final(hash_char, &sha256);

  for(i = 0; i < SHA_DIGEST_LENGTH; i++)
    o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<(int)hash_char[i];

  hash = o.str();
  o.str(std::string());
  msg_char = NULL; 
  delete[] msg_char;

  return hash;
}

/* A helper function that lets me encode ASCII values of a string as a string, especially for Country Name, City Name etc. 
   fields */
string ascii_str(string data)
{
  string as_str;
  int temp;
  ostringstream o;

  for(int i = 0; i < data.length(); i++)
      o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<(int)data[i];

  as_str = o.str();
  o.str(std::string());

  return as_str;

}

/* Function to get current time in UTC, for certificate validity */
string get_time(int days)
{
  char buffer[80], ayearlater[80];
  time_t rawtime;
  struct tm *timeinfo;
  string time_str;
  ostringstream o;
  int i;

  time(&rawtime);
  timeinfo = gmtime(&rawtime);

  time_str = "170D";
  strftime(buffer, 80, "%y%m%d%H%M%S", timeinfo);

  for(i = 0; buffer[i] != '\0'; i++)
    o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<(int)buffer[i];

  time_str += o.str() + "5A";
  o.str(std::string());

  while(days > 0)
    {
      days = ((timeinfo->tm_year)%4 == 0) ? (days-366) : (days-365);
      timeinfo->tm_year++;
    }

  time_str += "170D";
  strftime(ayearlater, 80, "%y%m%d%H%M%S", timeinfo);

  for(i = 0; ayearlater[i] != '\0'; i++)
    o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<(int)ayearlater[i];

  time_str += o.str() + "5A";
  o.str(std::string());

  return time_str;
}

/* Random string generator for version number of a certificate, and final signature of the certificate
   Reasons for choosing a random signature is given below (when this function is called) */
string gen_random_str(int length)
{
  BIGNUM *rand_bn = BN_new();
  string rand_str;

  BN_generate_prime(rand_bn, length, 0, NULL, NULL, NULL, NULL);
  rand_str = BN_bn2hex(rand_bn);

  BN_clear_free(rand_bn);

  return rand_str;

}

/* Function to pack user data such as Country Name, City Name, State name, Organization name, E-mail address
   that are stored in the ceritificate */
string user_data(string country_name, string state_name, string city_name, string org_name, string email_addr)
{
  string scratch1, scratch2, scratch3, scratch4;

  scratch1 = ascii_str(email_addr);
  scratch2 = "16" + i2s(scratch1.length()/2) + scratch1;

  scratch2 = "0609" + email_oid + scratch2;

  scratch3 = "30" + i2s(scratch2.length()/2) + scratch2;
  scratch3 = i2s(scratch3.length()/2) + scratch3;
  scratch3 = "31" + scratch3;
  scratch4 = scratch3;

  scratch1.erase();
  scratch2.erase();
  scratch3.erase();

  scratch1 = ascii_str(org_name);
  scratch2 = "0C" + i2s(scratch1.length()/2) + scratch1;

  scratch2 = "0603" + org_oid + scratch2;
  scratch3 = "30" + i2s(scratch2.length()/2) + scratch2 + scratch3;
  scratch3 = i2s(scratch3.length()/2) + scratch3;
  scratch4 = "31" + scratch3 + scratch4;

  scratch1.erase();
  scratch2.erase();
  scratch3.erase();

  scratch1 = ascii_str(city_name);
  scratch2 = "0C" + i2s(scratch1.length()/2) + scratch1;

  scratch2 = "0603" + city_oid + scratch2;
  scratch3 = "30" + i2s(scratch2.length()/2) + scratch2 + scratch3;
  scratch3 = i2s(scratch3.length()/2) + scratch3;
  scratch4 = "31" + scratch3 + scratch4;

  scratch1.erase();
  scratch2.erase();
  scratch3.erase();

  scratch1 = ascii_str(state_name);
  scratch2 = "0C" + i2s(scratch1.length()/2) + scratch1;

  scratch2 = "0603" + state_oid + scratch2;
  scratch3 = "30" + i2s(scratch2.length()/2) + scratch2 + scratch3;
  scratch3 = i2s(scratch3.length()/2) + scratch3;
  scratch4 = "31" + scratch3 + scratch4;

  scratch1.erase();
  scratch2.erase();
  scratch3.erase();

  scratch1 = ascii_str(country_name);
  scratch2 = "13" + i2s(scratch1.length()/2) + scratch1;

  scratch2 = "0603" + country_oid + scratch2;
  scratch3 = "30" + i2s(scratch2.length()/2) + scratch2 + scratch3;
  scratch3 = i2s(scratch3.length()/2) + scratch3;
  scratch4 = "31" + scratch3 + scratch4;

  scratch1.erase();
  scratch2.erase();
 
  scratch4 = i2s(scratch4.length()/2) + scratch4;
  scratch4 = "30" + scratch4;

  scratch3.erase();

  return scratch4;

}

/* Pack function for certificates, same functionality as asn1_public_pack */
string cert_asn1_pack(string *keyset, string country_name, string state_name, string city_name, string org_name, string email_addr, int days)
{

  string der_code, buffer, scratch, scratch1, buffer_sign, n, e, d, p, q, dp, dq, qinv;

  n = *keyset;
  e = *(keyset+1);
  d = *(keyset+2);
  p = *(keyset+3);
  q = *(keyset+4);
  dp = *(keyset+5);
  dq = *(keyset+6);
  qinv = *(keyset+7);

  buffer = "300C0603" +  basic_constraint_oid + "040530030101FF";
  scratch = sha_hash(n+e);
  buffer = "30168014" + scratch + buffer;
  buffer = "301F0603" + auth_key_id_oid + "0418" + buffer;

  buffer = "A350304E301D0603" + sub_key_oid + "04160414" + scratch + buffer; 
  scratch.erase();
  scratch = asn1_pub_pack(n, e, 0);
  buffer = scratch + buffer;

  scratch.erase();

  scratch = user_data(country_name, state_name, city_name, org_name,  email_addr);
  buffer = scratch + buffer;

  scratch.erase();

  scratch = get_time(days);
  buffer = i2s(scratch.length()/2) +scratch + buffer;
  buffer = "30" + buffer;

  scratch.erase();

  // Since this is a self-signed certificate, issuer data and subject data are same
  scratch = user_data(country_name, state_name, city_name, org_name, email_addr);
  buffer = scratch + buffer;

  scratch.erase();

  buffer = "300D0609" + sha_oid + "0500" + buffer;
  scratch = gen_random_str(72);
  buffer = scratch + buffer;
  buffer = "A0030201020209" + buffer;

  scratch.erase();

  buffer = i2s(buffer.length()/2) + buffer;
  buffer = "30" + buffer;

  // I'm generating a random value and storing it as signature, as I'm not going to validate it later.
  // Validating the signature is also not a required task for this project 
  buffer_sign = gen_random_str(n.length() * 4);                 
  buffer_sign = "300D0609" + sha_oid + "050003" + i2s(n.length()/2) + buffer_sign;
  
  buffer += buffer_sign;
  buffer = i2s(buffer.length()/2) + buffer;
  buffer = "30" + buffer;

  der_code = base64_encode(buffer);

  buffer.erase();
  scratch1.erase();

  return der_code;
}

/* Function to parse certificates to get the public and private keys for verification and signing respectively.
   Note: I do not parse the entire certificate, I'm storing the private and public keys before the certificate data.
   Hence, I do not parse the certificate data. */
int cert_asn1_parse(string filename, string *n, string *e, string *d, string *p, string *q, string *dp, string *dq, string *qinv)
{
  string decoded_string, scratch, buffer, scratch1, scratch2;
  fstream f;
  int err, i, t1, t2;

  f.open(filename.c_str(), ios::in);
  getline(f, scratch);
  scratch.erase();
  while(!f.eof())
     {
       getline(f, scratch);
       if(scratch == cert_priv_footer)
	 break;
       buffer += scratch;
       scratch.erase();
     }
  decoded_string = base64_decode(buffer);
  i = 0;

  if(decoded_string[i] != '3' || decoded_string[i+1] != '0')
    return 0;
  scratch1.assign(decoded_string, 2, decoded_string.length()-2);
  i += 2;
  scratch2.insert(0, 1, scratch1[0]);
  scratch2.insert(1, 1, scratch1[1]);

  i += 2;
  istringstream iss(scratch2);
  iss>>std::hex>>t1;

  if(t1 > 0x80)
    {
      t2 = t1 & 0x0F;
      i += t2*2;
    }
  iss.clear();
  t1 = 0;

  i += 38;

  scratch1.erase();
  scratch1.assign(decoded_string, i, decoded_string.length()-i);
  i += 2;
  scratch2.insert(0, 1, scratch1[0]);
  scratch2.insert(1, 1, scratch1[1]);

  i += 2;
  iss.str(scratch2);
  iss>>std::hex>>t1;

  if(t1 > 0x80)
    {
      t2 = t1 & 0x0F;
      i += t2*2;
    }
  iss.clear();
  t1 = 0;

  i = i-2;
  scratch1.erase();
  scratch1.assign(decoded_string, i, decoded_string.length()-i);

  if(e == NULL)
    err = asn1_private_parse(scratch1, n, NULL, d, p, q, dp, dq, qinv, 1);
  else  
    err = asn1_private_parse(scratch1, n, e, NULL, NULL, NULL, NULL, NULL, NULL, 1);
  if(!err)
    {
      cout<<"\nUnable to parse the certificate!!\n\n";
      return 0;
    }

  scratch.erase();
  scratch1.erase();
  scratch2.erase();
  decoded_string.erase();
  f.close();

  return 1;
  
}

/* Helper function to pack private key data before certificate data */
string cert_asn1_private_pack(string n, string e, string d, string p, string q, string dp, string dq, string qinv)
{
  string der_code, buffer, scratch;

  scratch = asn1_private_pack(n, e, d, p, q, dp, dq, qinv, 1);
  buffer = i2s(scratch.length() / 2) + scratch;
  buffer = "020100300D0609" + oid + "050004" + buffer;

  buffer = i2s(buffer.length() / 2) + buffer;
  buffer = "30" + buffer;

  der_code = base64_encode(buffer);
  scratch.erase();
  buffer.erase();

  return der_code;
}

/* Certificate generation call lands here. Just generates keys, and calls the private pack function.
   Doesn't do anything fancy */ 
int cert_gen(string filename, int bitcount)
{
  string country_name, city_name, state_name, org_name, fqdn_name, ou_name, email_addr, n, e, d, p, q, dp, dq, qinv, scratch;
  string *keyset;
  fstream f;
  int i = 0, validity_period;
 
  keyset = keygen(bitcount, std::string());
  n = *keyset;
  e = *(keyset+1);
  while(1)
    {
      cout<<"\nEnter the country name: ";
      cin>>country_name;
      if(country_name.length() != 2)
  	cout<<"\nEnter the 2 letter prefix of the country!\n\n";
      else 
  	break;
    }
  cout<<"\nEnter your city: ";
  cin>>city_name;
  cout<<"\nEnter your state: ";
  cin>>state_name;
  cout<<"\nEnter your org_name: ";
  cin>>org_name;
  cout<<"\nEnter your OU name: ";
  cin>>ou_name;
  cout<<"\nEnter your FQDN: ";
  cin>>fqdn_name;
  cout<<"\nEnter your e-mail address: ";
  cin>>email_addr;
  cout<<"\nEnter the validity peroid (in days): ";
  cin>>validity_period;

  string scratch1, temp, scratch2;
  scratch1 = cert_asn1_pack(keyset, country_name, state_name, city_name, org_name, email_addr, validity_period);

  d = *(keyset+2);
  p = *(keyset+3);
  q = *(keyset+4);
  dp = *(keyset+5);
  dq = *(keyset+6);
  qinv = *(keyset+7);

  scratch2 = cert_asn1_private_pack(n, e, d, p, q, dp, dq, qinv);

  f.open(filename.c_str(), ios::out);
  f<<cert_priv_header<<"\n";
  while(i < scratch2.length())
    {
      temp.assign(scratch2, i, 64);
      f<<temp<<"\n";
      i += 64;
      temp.erase();
    }
  f<<cert_priv_footer<<"\n";
  i = 0;
  f<<cert_file_header<<"\n";
  while(i < scratch1.length())
    {
      temp.assign(scratch1, i, 64);
      f<<temp<<"\n";
      i += 64;
      temp.erase();
    }
  f<<cert_file_footer;
  f.close();

  n.erase();
  e.erase();
  d.erase();
  p.erase();
  q.erase();
  dp.erase();
  dq.erase();
  qinv.erase();
  scratch.erase();
  scratch1.erase();
  temp.erase();
  country_name.erase();
  state_name.erase();
  city_name.erase();
  cout<<"\nCertificate \""<<filename<<"\" generated.\n\n";

  return 1;
}

/* Function used to sign data. Again, no padding scheme is used, hence file size has to be equal 
   modulus length */
int private_encrypt_data(string src_file, string priv_filename, string dest_file)
{
  string plain_text, signed_text, buffer, scratch, n_str, e_str, d_str, p_str, q_str, dp_str, dq_str, qinv_str;
  BIGNUM *c = BN_new();
  BIGNUM *m = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *m1 = BN_new();
  BIGNUM *m2 = BN_new();
  BIGNUM *h = BN_new();
  BIGNUM *p = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *dp = BN_new();
  BIGNUM *dq = BN_new();
  BIGNUM *qinv = BN_new();
  BIGNUM *scratch_num = BN_new();
  fstream f;
  int err, size;
  char *bin_write;

  err = cert_asn1_parse(priv_filename, &n_str, NULL, &d_str, &p_str, &q_str, &dp_str, &dq_str, &qinv_str);
  if(!err)
      return 0;

  BN_hex2bn(&n, n_str.c_str());
  BN_hex2bn(&p, p_str.c_str());
  BN_hex2bn(&q, q_str.c_str());
  BN_hex2bn(&dp, dp_str.c_str());
  BN_hex2bn(&dq, dq_str.c_str());
  BN_hex2bn(&d, d_str.c_str());
  BN_hex2bn(&qinv, qinv_str.c_str());

  f.open(src_file.c_str(), ios::in);
  getline(f, scratch);
  plain_text = scratch;
  while(!f.eof())
    {
      scratch.erase();
      getline(f, scratch);
      plain_text += "\n" + scratch;
    }
  f.close();

  if(plain_text.length() < BN_num_bytes(n))
    {
      cout<<"\nFile too small!!\n\n";
      return 0;
    }
  else if(plain_text.length() > BN_num_bytes(n))
    {
      cout<<"\nFile too large!!!\n\n";
      return 0;
    }

  m = os2ip(plain_text, 0);

  BN_mod_exp(m1, m, dp, p, ctx);              //RSASP1 operation starts here
  BN_mod_exp(m2, m, dq, q, ctx);              //Encryption using Chinese Remainder Algorithm
  if(BN_cmp(m1, m2) > 0)
    BN_sub(scratch_num, m1, m2);
  else
    {
      BN_sub(scratch_num, p, m2);
      BN_add(scratch_num, m1, scratch_num);
    }
  BN_mul(scratch_num, scratch_num, qinv, ctx);
  BN_mod(h, scratch_num, p, ctx);
  BN_clear(scratch_num);
  BN_mul(scratch_num, h, q, ctx);
  BN_add(c, m2, scratch_num);

  signed_text = i2osp(c, BN_num_bytes(n));

  f.open(dest_file.c_str(), ios::out | ios::binary);
  bin_write = new char[signed_text.length() + 1];
  for(int i = 0; i < signed_text.length(); i++)
    bin_write[i] = signed_text[i];
  f.seekp(0,ios::beg);
  f.write(bin_write, signed_text.length());
  f.close();

  bin_write = NULL;
  n_str.erase();
  p_str.erase();
  q_str.erase();
  dp_str.erase();
  dq_str.erase();
  qinv_str.erase();
  plain_text.erase();
  signed_text.erase();
  buffer.erase();
  scratch.erase();

  delete[] bin_write;
  BN_clear_free(m);
  BN_clear_free(c);
  BN_clear_free(m1);
  BN_clear_free(m2);
  BN_clear_free(h);
  BN_clear_free(scratch_num);
  BN_clear_free(n);
  BN_clear_free(p);
  BN_clear_free(q);
  BN_clear_free(dp);
  BN_clear_free(dq);
  BN_clear_free(qinv);
  BN_CTX_free(ctx);

  return 1;
}

/* Function to verify a given signed data */
int public_decrypt_data(string src_filename, string cert_filename)
{
  string verified_text, sign_text, buffer, scratch, mod, pub_exp;
  BIGNUM *m = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  fstream f;
  int err, size;
  char *bin_read;

  err = cert_asn1_parse(cert_filename, &mod, &pub_exp, NULL, NULL, NULL, NULL, NULL, NULL);
  if(!err)
    {
      cout<<"\n\nError: Unable to load Public key file\n\n";
      return 0;
    }

  BN_hex2bn(&n, mod.c_str());
  BN_hex2bn(&e, pub_exp.c_str());

  f.open(src_filename.c_str(), ios::in|ios::binary|ios::ate);
  size = f.tellg();
  bin_read = new char[size + 1];
  f.seekg(0, ios::beg);
  f.read(bin_read, size);
  f.close();

  sign_text.assign((const char *)bin_read, size);

  if(sign_text.length() > BN_num_bytes(n))
    {
      cout<<"\n\nFile too large!!!\n\n";
      return 0;
    }
  else if(sign_text.length() < BN_num_bytes(n))
    {
      cout<<"\nFile too small!!!\n\n";
      return 0;
    }

  m = os2ip(sign_text, 1);
  BN_mod_exp(c, m, e, n, ctx);                                  //RSAVP1 operation
  verified_text = i2osp(c, BN_num_bytes(n)); 

  cout<<verified_text<<endl;

  bin_read = NULL;
  mod.erase();
  pub_exp.erase();
  verified_text.erase();
  sign_text.erase();

  delete[] bin_read;
  BN_clear_free(n);
  BN_clear_free(e);
  BN_clear_free(m);
  BN_clear_free(c);
  BN_CTX_free(ctx);

  return 1;
}
