/* Custom ASN.1 parser. Does not implement all the specification of the parser. In fact, few values are just hard-coded.
   Few values or tags are not important for this project, and they're mostly the ones that are hard-coded */

#include<iostream>
#include<string>
#include<sstream>
#include<fstream>
#include<iomanip>
#include <openssl/bn.h>
#include "base64.h"
#include "asn1_parser.h"

using namespace std;

/* Function stands for Integer to String, but it does more than that. I use this function to calculate the length of the 
   each tag and it's contents. */
string i2s(int x)
{
  string str;
  int temp, x1;
  ostringstream c;
 
  if(x < 0xFF)
       c<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<x;
   else
       c <<std::hex<<std::uppercase<<setw(4)<<setfill('0')<<x;  

  str = c.str();
  c.str(std::string());

  if(x < 0x80)
    return str;
  temp = str.length();
  temp = ((temp % 2) == 1) ? ++temp : temp;
  temp = 0x80 | (temp / 2);
  c<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<temp;

  str = c.str() + str;

  return str;
}

/* Function to pack public key values (n and e) to a buffer, and write it out to a file with appropriate ASN.1 
   structure. Key files are base64 encoded PEM files, and not Binary encoded DER files. */
string asn1_pub_pack(string n, string e, int tag)
{
  int mod_length, pub_exp_length, tag_num;
  string buffer, mod_len_str,pub_exp_len_str, tag_type, scratch, der_code;
  ostringstream o;
  buffer.erase();

  mod_length = n.length();
  pub_exp_length = e.length();
  pub_exp_len_str = i2s(pub_exp_length / 2);
  mod_len_str = i2s(mod_length / 2);

  o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<ASN1_Integer;
  tag_type = o.str();
  buffer += tag_type + pub_exp_len_str + e;
  scratch = tag_type + mod_len_str + n;
  buffer = scratch + buffer;
  tag_type.erase();
  o.str(std::string());

  tag_num = ASN1_Sequence | ASN1_Constructed;
  o<<std::hex<<std::uppercase<<tag_num;
  tag_type = o.str();
  scratch = i2s(buffer.length()/2);
  buffer = "00" + tag_type + scratch + buffer;
  scratch.erase();
  tag_type.erase();
  o.str(std::string());

  tag_num = ASN1_Bit_string | ASN1_Primitive;
  o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<tag_num;
  tag_type = o.str();
  scratch = i2s(buffer.length() / 2);
  buffer = "0500" + tag_type + scratch + buffer;
  scratch.erase();
  tag_type.erase();
  o.str(std::string());

  tag_num = ASN1_OID | ASN1_Primitive;
  o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<tag_num;
  tag_type = o.str();
  scratch = i2s(oid.length() / 2);
  scratch = tag_type + scratch;
  o.str(std::string());

  tag_num = ASN1_Sequence | ASN1_Constructed;
  o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<tag_num;
  tag_type = o.str();
  buffer = tag_type + "0D" + scratch + oid + buffer;
  scratch.erase();
  o.str(std::string());
  tag_type.erase();

  tag_num = ASN1_Sequence | ASN1_Constructed;
  o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<tag_num;
  tag_type = o.str();
  scratch = i2s(buffer.length() / 2);
  buffer = tag_type + scratch + buffer;

  if(!tag)
    return buffer;  

  der_code = base64_encode(buffer);

  scratch.erase();
  o.str(std::string());
  tag_type.erase();
  buffer.erase();

  return der_code;
}

/* Function to parse the PEM file for a public key file, and extract (n,e) set from it. */
int asn1_public_parse(string base64_string, string *n, string *e)
{
  string scratch1, scratch2, decoded_string, temp_n, temp_e, obj_id;
  BIGNUM *mod = BN_new();
  BIGNUM *pub_exp = BN_new();
  int t1, t2 = 1, i = 0;

  decoded_string = base64_decode(base64_string);
  if(decoded_string[i] != '3' || decoded_string[i+1] != '0')      //Sequence
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

  if(decoded_string[i] != '3' || decoded_string[i+1] != '0')    //Sequence
    return 0;

  i += 4;
  scratch1.erase();
  scratch2.erase();

  if(decoded_string[i] != '0' || decoded_string[i+1] != '6')   //OID
    return 0;

  i += 2;
  scratch2.insert(0, 1, decoded_string[i]);
  scratch2.insert(1, 1, decoded_string[i+1]);
  iss.str(scratch2);
  iss >> t1;

  i += 2;
 
  scratch1.assign(decoded_string, i, decoded_string.length()-i);
  obj_id.assign(scratch1, 0, t1*2);

  if(obj_id != oid)
    {
      cout<<"\nEncryption identifier not recognized!\n";
      return 0;
    }

  i += t1*2;

  if(decoded_string[i] != '0' || decoded_string[i+1] != '5')   //NULL
    return 0;

  i += 2;

  if(decoded_string[i] != '0' || decoded_string[i+1] != '0')
    {
      cout<<"\nNULL tag does not contain NULL value!!\n";
      return 0;
    }

  i += 2;

  if(decoded_string[i] != '0' || decoded_string[i+1] != '3')  // Bit String
    return 0;

  i += 2;

  scratch2.erase();
  iss.clear();

  scratch2.insert(0, 1, decoded_string[i]);
  scratch2.insert(1, 1, decoded_string[i+1]);
  iss.str(scratch2);
  iss>>t1;

  if(t1 > 0x80)
    {
      t2 = t1 & 0x0F;
      i += (t2 +2)*2;
    }
  else
    i += 4;

  if(decoded_string[i] != '3' || decoded_string[i+1] != '0')   //Sequence
    return 0;

  i += 2;
  scratch2.erase();
  iss.clear();
  t1 = 0;

  scratch2.insert(0, 1, decoded_string[i]);
  scratch2.insert(1, 1, decoded_string[i+1]);
  i += 2;
  iss.str(scratch2);
  iss>>t1;

  t2 = 1;
  if(t1 > 0x80)
    {
      t2 = t1 & 0x0F;
      i += t2 * 2;
    }

  if(decoded_string[i] != '0' | decoded_string[i+1] != '2')   //Integer (Modulus)
    return 0;

  i += 2;

  *n = asn1_unpack(decoded_string, &i);

  if(decoded_string[i] != '0' || decoded_string[i+1] != '2')   //Integer (Public Exponent)
    return 0;
  i += 2;
  
  *e = asn1_unpack(decoded_string, &i);

  scratch1.erase();
  t1 = 0;
  scratch2.erase();
  temp_n.erase();
  temp_e.erase();

  BN_clear_free(mod);
  BN_clear_free(pub_exp);

  return 1;
}

/* Pack function for Private key files. Same purpose as asn1_pub_pack() function */
string asn1_private_pack(string n, string e, string d, string p, string q, string dp, string dq, string qinv, int tag)
{
  string der_code, buffer, tag_type, scratch;
  int len, tag_num;
  ostringstream o;

  scratch = i2s(qinv.length() / 2);
  tag_num = ASN1_Integer | ASN1_Primitive;
  o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<tag_num;
  tag_type = o.str();
  buffer = tag_type + scratch + qinv;
  scratch.erase();
  o.clear();

  scratch = i2s(dq.length() / 2);
  buffer = tag_type + scratch + dq + buffer;
  scratch.erase();

  scratch = i2s(dp.length() / 2);
  buffer = tag_type + scratch + dp + buffer;
  scratch.erase();

  scratch = i2s(q.length() / 2);
  buffer = tag_type + scratch + q + buffer;
  scratch.erase();

  scratch = i2s(p.length() / 2);
  buffer = tag_type + scratch + p + buffer;
  scratch.erase();
  
  scratch = i2s(d.length() / 2);
  buffer = tag_type + scratch + d + buffer;
  scratch.erase();
  
  scratch = i2s((e.length() / 2));
  buffer = tag_type + scratch + e + buffer;
  scratch.erase();
  
  scratch = i2s(n.length() / 2);
  buffer = tag_type + scratch + n + buffer;
  buffer = tag_type + "0100" + buffer;
  scratch.erase();
  tag_type.erase();
  o.str(std::string());
  
  tag_num = ASN1_Sequence | ASN1_Constructed;
  o<<std::hex<<std::uppercase<<setw(2)<<setfill('0')<<tag_num;
  tag_type = o.str();
  scratch = i2s((buffer.length() / 2));
  buffer = tag_type + scratch + buffer;
  
  if(tag)
    return buffer;

  der_code = base64_encode(buffer);

  buffer.erase();
  scratch.erase();
  o.str(std::string());

  return der_code;
}

/* Function to parse a private key file, and extract the required keys */
int asn1_private_parse(string der_code, string *n, string *e, string *d, string *p, string *q, string *dp, string *dq, string *qinv, int tag)
{

  string scratch1, buffer, temp, scratch2, decoded_string;
  int i = 0, num, num1;
  istringstream iss;
  const char *temp_char;

  buffer.erase();
  scratch1.erase();
  scratch2.erase();
  temp.erase();

  if(tag)
    decoded_string = der_code;
  else
    decoded_string = base64_decode(der_code);

  if(decoded_string[i] != '3' || decoded_string[i+1] != '0')               //Sequence
    return 0;

  i += 2;
  scratch1.assign(decoded_string, i, decoded_string.length() - i);

  scratch2.insert(0, 1, decoded_string[i]);
  scratch2.insert(1, 1, decoded_string[i+1]);

  i += 2;

  iss.str(scratch2);
  iss>>std::hex>>num;

  if(num > 0x80)
    {
      num1 = num & 0x0F;
      i += num1*2;
    }

  if(decoded_string[i] != '0' || decoded_string[i+1] != '2')              //Integer
    return 0;                                                            //Reserved for future version, hence this
                                                                         //can be ignored
  i += 6;

  if(decoded_string[i] != '0' || decoded_string[i+1] != '2')             //Integer
    return 0;

  i += 2;

  scratch1.erase();

  if(n != NULL)
    *n = asn1_unpack(decoded_string, &i);
  else
    scratch1 = asn1_unpack(decoded_string, &i);

  scratch1.erase();

  if(decoded_string[i] != '0' || decoded_string[i+1] != '2')             //Integer
    return 0;

  i += 2;

  if(e != NULL)
    *e = asn1_unpack(decoded_string, &i);
  else
    scratch1 = asn1_unpack(decoded_string, &i);

  scratch1.erase();
  if(decoded_string[i] != '0' || decoded_string[i+1] != '2')              //Integer
    return 0;

  i += 2;

  scratch1.erase();
  if(d != NULL)
    *d = asn1_unpack(decoded_string, &i);
  else
    scratch1 = asn1_unpack(decoded_string, &i);

  scratch1.erase();

  if(decoded_string[i] != '0' || decoded_string[i+1] != '2')              //Integer
    return 0;

  i += 2;

  if(p != NULL)
    *p = asn1_unpack(decoded_string, &i);
  else
    scratch1 = asn1_unpack(decoded_string, &i);

  scratch1.erase();

  if(decoded_string[i] != '0' || decoded_string[i+1] != '2')              //Integer
    return 0;

  i += 2;

  if(q != NULL)
    *q = asn1_unpack(decoded_string, &i);
  else
    scratch1 = asn1_unpack(decoded_string, &i);

  scratch1.erase();

  if(decoded_string[i] != '0' || decoded_string[i+1] != '2')               //Integer
    return 0;

  i += 2;

  if(dp != NULL)
    *dp = asn1_unpack(decoded_string, &i);
  else
    scratch1 = asn1_unpack(decoded_string, &i);
  
  scratch1.erase();

  if(decoded_string[i] != '0' || decoded_string[i+1] != '2')                //Integer
    return 0;

  i += 2;

  if(dq != NULL)
    *dq = asn1_unpack(decoded_string, &i);
  else
    scratch1 = asn1_unpack(decoded_string, &i);
  
  scratch1.erase();

 if(decoded_string[i] != '0' || decoded_string[i+1] != '2')                 //Integer
    return 0;

  i += 2;

  if(qinv != NULL)
    *qinv = asn1_unpack(decoded_string, &i);
  else
    scratch1 = asn1_unpack(decoded_string, &i);
  
  scratch1.erase();
  buffer.erase();

   return 1;
}

/* A helper function to the asn1_private_parse and asn1_pub_parse function to get me the values contained in a tag */
string asn1_unpack(string decoded_string, int* iterator)
{
  int num, num1 = 1, size;
  stringstream ss;
  string scratch, scratch1;

  scratch.insert(0, 1, decoded_string[*iterator]);
  scratch.insert(1, 1, decoded_string[(*iterator) + 1]);

  ss.str(scratch);
  ss>>std::hex>>num;

  ss.clear();

  if(num > 0x80)
    {
      num1 = num & 0x0F;
      *iterator = *iterator + 2;
    }

  scratch1.assign(decoded_string, *iterator, num1*2);
  ss.str(scratch1);
  ss>>std::hex>>size;
  *iterator = *iterator + num1*2;
  ss.clear();

  scratch.erase();
  scratch.assign(decoded_string, *iterator, size*2);

  *iterator = *iterator + size*2;

  return scratch;
}
