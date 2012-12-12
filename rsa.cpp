/* Contains modules that perform the key generation, encryption and decryption of data. This file does not have certificate 
   related modules. Encryption and decryption is done without any padding scheme. */

#include<iostream>
#include<string>
#include<sstream>
#include<fstream>
#include<cstring>
#include<openssl/bn.h>
#include "rsa.h"
#include "asn1_parser.h"
#include "cert.h"

using namespace std;

/* I2OSP function to convert an Integer into Octet String representative, as described in RFC */
string i2osp(BIGNUM *c, int mod_length)
{
  BIGNUM *temp = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *num256 = BN_new();
  string scratch;

  BN_set_word(num256, 256);
  while(!(BN_is_zero(c)))
    {
      BN_mod(temp, c, num256, ctx);
      scratch += BN_get_word(temp);
      BN_div(c, NULL, c, num256, ctx);
    }
  while(scratch.length() < mod_length)
    scratch += "\x00";

  BN_clear_free(temp);
  BN_clear_free(num256);
  BN_CTX_free(ctx);

  scratch = std::string(scratch.rbegin(), scratch.rend());
  return scratch;
}

/* I2OSP function to convert an Octet String into Integer representative, as described in RFC */
BIGNUM * os2ip(string m, int tag)
{
  BIGNUM *temp = BN_new();
  BIGNUM *scratch = BN_new();
  BIGNUM *num256 = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  int i, t;

  BN_set_word(num256, 256);

  for(i = 0; i < m.length(); i++)
    {
      t = m[i];
      if(tag)
	t = t & 0xFF;
      BN_set_word(scratch, t);
      BN_mul(temp, temp, num256, ctx);
      BN_add(temp, temp, scratch);
    }

  BN_clear_free(scratch);
  BN_CTX_free(ctx);
  BN_clear_free(num256);

  return temp;
}

/* Actual Encryption module that encrypts a source file supplied as argument */
int encrypt_data(string src_file, string public_key_file, string dest_file)
{
  string plain_text, der_string, cipher_text, buffer, scratch, mod, pub_exp;
  BIGNUM *m = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  fstream f;
  int err;
  char *bin_write;

  cipher_text.erase();

  f.open(public_key_file.c_str(), ios::in);
  getline(f, scratch);
  while(!f.eof())
    {
      scratch.erase();
      getline(f, scratch);
      if(scratch == pub_file_footer)
	break;
      der_string += scratch;
    }
  scratch.erase();
  f.close();

  err = asn1_public_parse(der_string, &mod, &pub_exp);
  if(!err)
    {
      cout<<"\n\nError: Unable to load Public key file\n\n";
      return 0;
    }

  BN_hex2bn(&n, mod.c_str());
  BN_hex2bn(&e, pub_exp.c_str());

  f.open(src_file.c_str(), ios::in);
  getline(f, plain_text);
  while(!f.eof())
    {
      getline(f, buffer);
      plain_text += "\n" + buffer;
      buffer.erase();
    }
  buffer.erase();
  f.close();

  /* Since no padding scheme is used, file size has to be exactly equal to the Modulus length */
  if(plain_text.length() > BN_num_bytes(n))
    {
      cout<<"\n\nFile too large!!!\n\n";
      return 0;
    }
  else if(plain_text.length() < BN_num_bytes(n))
    {
      cout<<"\nFile too small!!!\n\n";
      return 0;
    }

  m = os2ip(plain_text, 0);
  BN_mod_exp(c, m, e, n, ctx); //RSAEP operation
  cipher_text = i2osp(c, BN_num_bytes(n)); 

  f.open(dest_file.c_str(), ios::out | ios::binary);
  bin_write = new char[cipher_text.length() + 1];
  for(int i = 0; i < cipher_text.length(); i++)
    bin_write[i] = cipher_text[i];
  f.seekp(0,ios::beg);
  f.write(bin_write, cipher_text.length());
  f.close();

  bin_write = NULL;
  mod.erase();
  pub_exp.erase();
  plain_text.erase();
  cipher_text.erase();

  delete[] bin_write;
  BN_clear_free(n);
  BN_clear_free(e);
  BN_clear_free(m);
  BN_clear_free(c);
  BN_CTX_free(ctx);

  return 1;
}

/* Decryption module that decrypts an already encrypted text with private key supplied as one of the argument */
int decrypt_data(string src_file, string priv_filename, string dest_file)
{
  string cipher_text, decrypted_text, buffer, scratch, n_str, e_str, d_str, p_str, q_str, dp_str, dq_str, qinv_str, der_string;
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
  char *bin_read;

  decrypted_text.erase();

  f.open(priv_filename.c_str(), ios::in);
  getline(f, scratch);
  scratch.erase();
  while(!f.eof())
    {
      getline(f, scratch);
      if(scratch == priv_file_footer)
	break;
      der_string += scratch;
      scratch.erase();
    }
  f.close();

  err = asn1_private_parse(der_string, &n_str, NULL, &d_str, &p_str, &q_str, &dp_str, &dq_str, &qinv_str, 0);
  if(!err)
    {
      cout<<"\n\nUnable to load private key!!!\n\n";
      return 0;
    }

  BN_hex2bn(&n, n_str.c_str());
  BN_hex2bn(&p, p_str.c_str());
  BN_hex2bn(&q, q_str.c_str());
  BN_hex2bn(&dp, dp_str.c_str());
  BN_hex2bn(&dq, dq_str.c_str());
  BN_hex2bn(&d, d_str.c_str());
  BN_hex2bn(&qinv, qinv_str.c_str());

  f.open(src_file.c_str(), ios::in|ios::binary|ios::ate);
  size = f.tellg();
  bin_read = new char[size + 1];
  f.seekg(0, ios::beg);
  f.read(bin_read, size);
  f.close();

  cipher_text.assign((const char *)bin_read, size);
  delete[] bin_read;

  if(cipher_text.length() < BN_num_bytes(n))
    {
      cout<<"\nFile too small!!\n\n";
      return 0;
    }
  else if(cipher_text.length() > BN_num_bytes(n))
    {
      cout<<"\nFile too large!!!\n\n";
      return 0;
    }

  c = os2ip(cipher_text, 1);

  BN_mod_exp(m1, c, dp, p, ctx);              //RSADP operation starts here
  BN_mod_exp(m2, c, dq, q, ctx);               //Decryption using Chinese Remainder Algorithm
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
  BN_add(m, m2, scratch_num);

  decrypted_text = i2osp(m, BN_num_bytes(n));

  f.open(dest_file.c_str(), ios::out);
  f<<decrypted_text;
  f.close();

  n_str.erase();
  p_str.erase();
  q_str.erase();
  dp_str.erase();
  dq_str.erase();
  qinv_str.erase();
  decrypted_text.erase();
  buffer.erase();
  scratch.erase();
  der_string.erase();

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

/* Key generation module. Strength of the key taken as an input from the user */
string* keygen(int bitcount, string filename)
{

  string mod, priv_exp, pub_exp, prime1, prime2, exponent1, exponent2, co_efficient, buffer, scratch;
  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *phi = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *d = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *pminus1 = BN_new();
  BIGNUM *qminus1 = BN_new();
  BIGNUM *e_check = BN_new();
  BIGNUM *gcd = BN_new();
  BIGNUM *dp = BN_new();
  BIGNUM *dq = BN_new();
  BIGNUM *qinv = BN_new();
  fstream f;
  string* keyset = new string[8];


  BN_generate_prime(p, bitcount/2, 0, NULL, NULL, NULL, NULL);
  BN_generate_prime(q, bitcount/2, 0, NULL, NULL, NULL, NULL);
  BN_mul(n, p, q, ctx);
  BN_sub(pminus1, p, BN_value_one());
  BN_sub(qminus1, q, BN_value_one());
  BN_mul(phi, pminus1, qminus1, ctx);
  BN_set_word(e_check, 13);
  while(1)
   {
     BN_generate_prime(e, 16, 0, NULL, NULL, NULL, NULL);
     if(BN_cmp(e, e_check) <= 0)
       continue;
     BN_gcd(gcd, e, phi, ctx);
     if(!BN_cmp(gcd,BN_value_one()))
       break;
   }
  BN_mod_inverse(d, e, phi, ctx);
  BN_mod(dp, d, pminus1, ctx);
  BN_mod(dq, d, qminus1, ctx);
  BN_mod_inverse(qinv, q, p, ctx);

  mod = BN_bn2hex(n);
  priv_exp = BN_bn2hex(d);
  pub_exp = BN_bn2hex(e);
  prime1 = BN_bn2hex(p);
  prime2 = BN_bn2hex(q);
  exponent1 = BN_bn2hex(dp);
  exponent2 = BN_bn2hex(dq);
  co_efficient = BN_bn2hex(qinv);

  BN_clear_free(p);
  BN_clear_free(q);
  BN_clear_free(n);
  BN_clear_free(e);
  BN_clear_free(d);
  BN_clear_free(phi);
  BN_clear_free(dp);
  BN_clear_free(dq);
  BN_clear_free(qinv);
  BN_clear_free(pminus1);
  BN_clear_free(qminus1);
  BN_clear_free(gcd);
  BN_clear_free(e_check);
  if(ctx != NULL)
    BN_CTX_free(ctx);

  buffer = asn1_private_pack(mod, pub_exp, priv_exp, prime1, prime2, exponent1, exponent2, co_efficient, 0);

  if(filename.empty())
    {
      keyset[0] = mod;
      keyset[1] = pub_exp;
      keyset[2] = priv_exp;
      keyset[3] = prime1;
      keyset[4] = prime2;
      keyset[5] = exponent1;
      keyset[6] = exponent2;
      keyset[7] = co_efficient;
      return keyset;
    }
  f.open(filename.c_str(), ios::out);
  int i = 0;
  f<<priv_file_header<<"\n";
  scratch.erase();
  while(i < buffer.length())
    {
      scratch.assign(buffer, i, 64);
      i += 64;
      f<<scratch<<"\n";
      scratch.erase();
    }
  i = 0;
  scratch.erase();
  f<<priv_file_footer;

  f.close();
  scratch.erase();
  buffer.erase();
  mod.erase();
  pub_exp.erase();
  priv_exp.erase();
  prime1.erase();
  prime2.erase();
  exponent1.erase();
  exponent2.erase();
  co_efficient.erase();

  cout<<"\n\nPrivate key written to file \""<<filename<<"\""<<endl<<endl;
  return NULL;
}

/* An extension of Key generation; extracts the public key from an already existing private key file */
void gen_pubkey(string priv_filename, string pub_filename)
{
  string buffer, scratch, mod, pub_exp, der_code;
  int i;
  fstream f;

  f.open(priv_filename.c_str(), ios::in);
  getline(f, scratch); //ignore header
  while(!f.eof())
    {
      scratch.erase();
      getline(f, scratch);
      if(scratch == priv_file_footer) //ignore footer
	break;
      der_code += scratch;
    }
  f.close();

  i = asn1_private_parse(der_code, &mod, &pub_exp, NULL, NULL, NULL, NULL, NULL, NULL, 0);
  if(!i)
    {
      cout<<"\nASN Parser error. Private key PEM file could not be parsed!!\n\n";
      return;
    }
  der_code.erase();

  der_code = asn1_pub_pack(mod, pub_exp, 1);

  f.open(pub_filename.c_str(), ios::out);
  i = 0;
  f<<pub_file_header<<"\n";
  while(i < der_code.length())
    {
      scratch.erase();
      scratch.assign(der_code, i, 64);
      i += 64;
      f<<scratch<<"\n";
    }
  f<<pub_file_footer;

  i = 0;
  mod.erase();
  pub_exp.erase();
  scratch.erase();
  der_code.erase();
  f.close();

  cout<<"\n\nPublic key written to file \""<<pub_filename<<"\""<<endl<<endl;
  return;

}
