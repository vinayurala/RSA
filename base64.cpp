/* Contains modules that does Base64 encoding */

#include <iostream>
#include <string>
#include<iomanip>
#include<sstream>

using namespace std;

/* Return the Base64 code given a character */
char return_encode_char(int i)
{
  if (i < 26)
    return ('A' + i);
  else if ((i >= 26) && (i < 52))
    return ('a' + (i-26));
  else if ((i >= 52) && (i < 62))
    return ('0' + (i-52));
  return (i == 62 ? '+' : '/');
}

/* Returns a ASCII character given a Base64 code */
int return_decode_int(char i)
{
  if ((i >= 'A') && (i <= 'Z'))
    return (i - 65);
  else if ((i >= 'a') && (i <= 'z'))
    return (i - 71);
  else if ((i >= '0') && (i <= '9'))
    return (i + 4);
  else if (i == '=')
    return 0; 
 return (i == '+' ? 62 : 63);
}

/* Helper function to convert Integer to String */
int s2i_base64(char t1, char t2)
{
  string s = std::string();

  s.insert(0, 1, t1);
  s.insert(1, 1, t2);
  istringstream i(s);
  int res;

  i>>std::hex>>res;

  return res;
}

/* Helper function to convert Integer to String */
string i2s_base64(int num)
{
  string s;
  ostringstream o;

  o << std::hex<<std::uppercase<<setw(2)<<setfill('0')<<num;

  s = o.str();
  o.str(std::string());

  return s;
}

/* Function to encode a given string to base64 code */
string base64_encode(string str)
{
  string base64_str;
  int i, j, octet[3], encode[6000], count = 0, len;
  len = str.length();
  for (i = 0, j = 0; i < len; i+=6, j+=4)
    {
      // Convert 3 octets into 4 6-bit base64 encoded values
      octet[0] = s2i_base64(str[i], str[i+1]);
      octet[1] = s2i_base64(str[i+2], str[i+3]);
      octet[2] = s2i_base64(str[i+4], str[i+5]);
      encode[j] = ((octet[0] & 0xFC) >> 2);
      encode[j+1] = ((octet[0] & 0x03) << 4) | ((octet[1] & 0xF0) >> 4);
      encode[j + 2] = ((octet[1] & 0x0F) << 2) | ((octet[2] & 0xC0) >> 6);
      encode[j+3] = octet[2] & 0x3F ;
      count += 4;
    }
  base64_str.erase();
  for (j = 0; j < count; j++)
    base64_str += return_encode_char(encode[j]);
  len /= 2;
  // Takes care of padding, if length is not a mutliple of 3. 
  if(len % 3 == 2)
    base64_str[base64_str.length()-1] = '=';
  else if(len % 3 == 1)
    base64_str[base64_str.length()-1] = base64_str[base64_str.length()-2] = '=';

   return base64_str;
}

/* Function to decode a base64 encoded string into an ASCII string */
string base64_decode(string base64_str)
{
  string str, octet;
  int *base64_int = new int[6000];
  int i, j,  decode[4], len = 0, scratch;
  for (i = 0; base64_str[i] != '\0'; i++)
    {
      base64_int[i] = return_decode_int(base64_str[i]);
      len++;
    }
  for (i = 0, j = 0; i < len; i+=4, j+=3)
    {
      // Convert 4 6-bit base64 encoded values into 3 octets
      decode[0] = base64_int[i];
      decode[1] = base64_int[i+1];
      decode[2] = base64_int[i+2];
      decode[3] = base64_int[i+3];
      scratch = (decode[0] << 2) | (decode[1] >> 4);
      octet += i2s_base64(scratch);
      scratch = ((decode[1] & 0x0F) << 4 | (decode[2] & 0x3C) >> 2);
      octet += i2s_base64(scratch);
      scratch = ((decode[2] & 0x03) << 6) | decode[3];
      octet += i2s_base64(scratch);
    }
  // Ignore padding characters at the end
   if(base64_str[base64_str.length()-2] == '=')
      octet.replace(octet.length()-4, 4, 4, '\0');
   else if(base64_str[base64_str.length()-1] == '=')
      octet.replace(octet.length()-2, 2, 2, '\0');

  base64_int = NULL;
  delete[] base64_int;

  return octet;
}

