#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include <iostream>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>


#ifdef  __cplusplus
extern "C" {
#endif
#include <openssl/applink.c>
#ifdef  __cplusplus
}
#endif

using namespace std;

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext, int mode)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (mode == 1) {
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
      handleErrors();
  } // if 
  else if (mode == 2) {
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
      handleErrors();
  } // else if 
  else {
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
      handleErrors();
  } // else 


  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext, int mode)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */

  if (mode == 1) {
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
      handleErrors();
  } // if 
  else if (mode == 2) {
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
      handleErrors();
  } // if 
  else {
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
      handleErrors();
  } // else

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void Readplaintextfile(string &filename, string &plaintext) {
  fstream file;
  plaintext = "";
  filename = "";
  cout << "請輸入檔案名稱: ";
  getline(cin, filename);
  getline(cin, filename);
  filename = filename + ".txt";
  file.open(filename, ios::in);
  if (!file)
    cout << "檔案無法開啟\n";
  else {
    while (getline(file, plaintext)) {
      cout << "text: " << plaintext << endl;
    }
    file.close();
  } // else 
} // Readplaintextfile()

void Readciphertextfile(string & inputfilename, int EncodeOrDecode, char* & ciphertext, int &filesize, int mode ) {
  FILE *file;
  cout << "請輸入檔案名稱: ";
  getline(cin, inputfilename);
  getline(cin, inputfilename);

  if (EncodeOrDecode == 2) {
    if (mode == 1) 
      inputfilename = inputfilename + "_CBC_Encode.txt";
    else if (mode == 2) 
        inputfilename = inputfilename + "_ECB_Encode.txt";
    else 
      inputfilename = inputfilename + "_CTR_Encode.txt";
  } // if 

  file = fopen(inputfilename.c_str(), "rb");
  if (!file)
    cout << "檔案無法開啟\n";
  else {
    fseek(file, 0, SEEK_END);
    filesize = ftell(file);
    rewind(file);
    ciphertext = (char*)malloc(sizeof(char)* filesize);
    int readsize = fread(ciphertext, 1, filesize, file);
    if (readsize != filesize) {
      fputs("Reading error", stderr);
      exit(3);
    } // if 

    for (int i = 0; i < filesize; i++) {
      if (ciphertext[i] == '\n') {
        for (int j = i-1; j < filesize - 1; j++) {
          ciphertext[j] = ciphertext[j + 1];
        } // for 

        filesize--;
      } // if 
    } // for 
  } // else 
} // Readplaintextfile()

void Outputfile( string inputfilename, int EncodeOrDecode, const char *text, int filesize, int mode) {
  fstream file;
  string outputfilename = "";
  int pos = inputfilename.find_first_of(".", 0);
  outputfilename = inputfilename.substr(0, pos - 0);

  if (EncodeOrDecode == 1) {
    if (mode == 1)
      outputfilename = outputfilename + "_CBC_Encode.txt";
    else if (mode == 2)
      outputfilename = outputfilename + "_ECB_Encode.txt";
    else 
      outputfilename = outputfilename + "_CTR_Encode.txt";
  } // if 
  else {
    outputfilename = outputfilename + "_Decoded.txt";
  } // else 

  file.open(outputfilename, ios::out);
  if (!file)
    cout << "檔案無法開啟\n";
  else {
    file.write(text, filesize);   //將str寫入檔案
    file.close();       //關閉檔案
  } // else 
} // Outputfile() 

void UserInput(string &key, string &InitialVector, int &EncodeOrDecode, int &mode) {
  cout << "請輸入key值: ";
  cin >> key;
  //key = "01234567890123456789012345678901";
  cout << "請輸入Initial Vector: ";
  cin >> InitialVector;
  //InitialVector = "0123456789012345";
  cout << "請輸入要encode還是decode(1.en 2.de): ";
  cin >> EncodeOrDecode;
  cout << "請輸入mode(1.CBC 2.ECB 3.CTR): ";
  cin >> mode;
} // UserInput()

int main() {
  /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

  int go = 1;
  double starttime, endtime, totaltime;
  double performance;

  while (go) {
    unsigned char *key = (unsigned char *)"";
    string key_str = "";
    unsigned char *iv = (unsigned char *)"";
    string iv_str = "";

    string inputfilename;
    unsigned char *plaintext = (unsigned char *)"";
    string plaintext_str = "";

    int EncodeOrDecode = 0;
    int mode = 0;
    int filesize = 0;

    unsigned char ciphertext[128];
    char *ciphertext_chr = new char();

    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len = 0;

    UserInput(key_str, iv_str, EncodeOrDecode, mode);
    key = (unsigned char*)key_str.c_str();
    iv = (unsigned char*)iv_str.c_str();
    if (EncodeOrDecode == 1) {
      Readplaintextfile(inputfilename, plaintext_str);
      plaintext = (unsigned char*)plaintext_str.c_str();

      starttime = clock();
      ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext, mode);
      endtime = clock();
      totaltime = (endtime - starttime) / CLOCKS_PER_SEC;
      performance = (filesize * 1024 * 1024) / totaltime;

      printf("Ciphertext is:\n");
      BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
      Outputfile(inputfilename, EncodeOrDecode, (const char *)ciphertext, ciphertext_len, mode);
      printf("加密的執行效率:%lf MB/s\n", performance);
    } // if 
    else if (EncodeOrDecode == 2) {
      Readciphertextfile(inputfilename, EncodeOrDecode, ciphertext_chr, filesize, mode);
      unsigned char* buffer = (unsigned char*)ciphertext_chr;
      BIO_dump_fp(stdout, (const char*)buffer, filesize);

      starttime = clock();
      decryptedtext_len = decrypt((unsigned char*)ciphertext_chr, filesize, key, iv, decryptedtext, mode);
      endtime = clock();
      totaltime = (endtime - starttime) / CLOCKS_PER_SEC;
      performance = (filesize * 1024 * 1024) / totaltime;

      decryptedtext[decryptedtext_len] = '\0';
      printf("Decrypted text is:\n");
      printf("%s\n", decryptedtext);
      cout << endl << "我的decryptedtext:" << decryptedtext << endl;
      Outputfile(inputfilename, EncodeOrDecode, (const char *)decryptedtext, decryptedtext_len, mode);

      printf("解密的執行效率:%lf MB/s\n", performance);
    } // else if 

    cout << "gogo?(1.yes 0.no): ";
    cin >> go;
  } // while 
} // main()