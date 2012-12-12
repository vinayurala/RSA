/* Main Invoker function which calls the other modules in other files, such as to encrypt and decrypt data,
   generate key and ceritifcate files, and verify and sign data */

#include<iostream>
#include<fstream>
#include<string>
#include "rsa.h"
#include "asn1_parser.h"
#include "cert.h"

using namespace std;

int main(int argc, char **argv)
{

  int ch, bitcount;
  string priv_filename, pub_filename, src_file, dest_file, cert_file;
  fstream f;
  cout<<"\n1. Generate private key.\n2. Generate public key.\n3. Encrypt a file using a key\n4. Decrypt a file using Private key\n5. Generate a X.509 certificate with public and private keys\n6. Sign data with an exisitng certificate\n7. Verify signed data with an exisitng certificate\n8. Display choices\n9. Exit\n\n";
  while(1)
    {
      cout<<"\nEnter choice: ";
      cin>>ch;
      switch(ch)
	{
	case 1: cout<<"\nEnter the desired key strength(key size in bits): ";
	        cin>>bitcount;
	        if(bitcount < 129)
	        {
		  cout<<"\nKey too weak; re-start.......!!\n"<<endl;
		  break;
		}
	        cout<<"\nEnter the filename of the key file: ";
	        cin>>priv_filename;
	        keygen(bitcount, priv_filename);
	        break;
	case 2: cout<<"\nEnter the private keyfile from which you wish to generate public key: ";
	        cin>>priv_filename;
		f.open(priv_filename.c_str(), ios::in);
		if(!(f.good()))
		  {
		    cout<<"\nFile "<<priv_filename<<" does not exist!!Do-over again......\n\n";
		    break;
		  }
		f.close();
		cout<<"\nEnter the name of the public key file:";
		cin>>pub_filename;
		gen_pubkey(priv_filename, pub_filename);
		break;
	case 3: cout<<"\nEnter the source file name: ";
                cin>>src_file;
		f.open(src_file.c_str(), ios::in);
		if(!f.good())
		  {
		    cout<<"\n\nFile \""<<src_file<<"\"does not exist!!Start over again......\n\n";
		    break;
		  }
		f.close();
		cout<<"\nEnter the file name containing your public key: ";
		cin>>pub_filename;
		f.open(pub_filename.c_str(), ios::in);
		if(!f.good())
		  {
		    cout<<"\n\nFile \""<<pub_filename<<"\"does not exist!!Start over again......\n\n";
		    break;
		  }
		f.close();
		cout<<"\nEnter the name of the file where cipher text can be written to: ";
		cin>>dest_file;
		encrypt_data(src_file, pub_filename, dest_file);
		break;
	case 4: cout<<"\nEnter the source file name: ";
                cin>>src_file;
		f.open(src_file.c_str(), ios::in);
		if(!f.good())
		  {
		    cout<<"\n\nFile \""<<src_file<<"\"does not exist!!Start over again......\n\n";
		    break;
		  }
		f.close();
		cout<<"\nEnter the file name containing your private key: ";
		cin>>priv_filename;
		f.open(priv_filename.c_str(), ios::in);
		if(!f.good())
		  {
		    cout<<"\n\nFile \""<<priv_filename<<"\"does not exist!!Start over again......\n\n";
		    break;
		  }
		f.close();
		cout<<"\nEnter the name of the file where decrypted text can be written to: ";
		cin>>dest_file;
		decrypt_data(src_file, priv_filename, dest_file);
		break;
	case 5: cout<<"\nEnter the the key size: ";
                cin>>bitcount;
		cout<<"\nEnter the name for the certificate file: ";
		cin>>src_file;
		cert_gen(src_file, bitcount);
		break;
	case 6: cout<<"\nEnter the file name which you would wish to sign: ";
                cin>>src_file;
		f.open(src_file.c_str(), ios::in);
		if(!f.good())
		  {
		    cout<<"\nFile \""<<src_file<<"\" does not exist!!Start over again......\n\n";
		    break;
		  }
		f.close();
		cout<<"\nEnter the name of the certificate file: ";
		cin>>cert_file;
		f.open(cert_file.c_str(), ios::in);
		if(!f.good())
		  {
		    cout<<"\nFile \""<<cert_file<<"\" does not exist!!Start over again.......\n\n";
		    break;
		  }
		f.close();
		cout<<"\nEnter the destination file, where signature can be stored: ";
		cin>>dest_file;
		private_encrypt_data(src_file, cert_file, dest_file);
		break;
	case 7: cout<<"\nEnter the file name which you would like to verify: ";
                cin>>src_file;
		f.open(src_file.c_str(), ios::in);
		if(!f.good())
		  {
		    cout<<"\nFile \""<<src_file<<"\" does not exist!!Start over again.....\n\n";
		    break;
		  }
		f.close();
		cout<<"\nEnter the name of the certificate file: ";
		cin>>cert_file;
		f.open(cert_file.c_str(), ios::in);
		if(!f.good())
		  {
		    cout<<"\nFile \""<<cert_file<<"\" does not exist!!Start over again......\n\n";
		    break;
		  }
		f.close();
		public_decrypt_data(src_file, cert_file);
		break;
	case 8: cout<<"\n1. Generate private key.\n2. Generate public key.\n3. Encrypt a file using a key\n4. Decrypt a file using Private key\n5. Generate a X.509 certificate with public and private keys\n6. Sign data with an exisitng certificate\n7. Verify signed data with an exisitng certificate\n8. Display choices\n9. Exit\n\n";
	        break;
	case 9: cout<<endl;
	        return 0;
	default: cout<<"\nInvalid choice!! Press 8 to see the choices again\n\n";
	         break;
	}
    }
}
