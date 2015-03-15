#include "aes.h"

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/*Initialise 256 bit key and IV for cipher. Returns 0 on success, 1 on failure*/
int aes_init(const char *keydata, unsigned int keydata_len, unsigned char *key, unsigned char *iv)
{
  const unsigned char *salt = "1234554321";

  if(!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, (unsigned char *) keydata, keydata_len, 5, key, iv))
  {
      fprintf(stderr, "EVP_BytesToKey failed\n");
      return 1;
  }
  return 0;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) 
    handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int main(int argc, char *argv[])
{
  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
  const char *password = "password";
  int i;

  unsigned char plaintext[1024], ciphertext[1024];
  int len;
  strcpy(plaintext,"Kunal Baweja");

  aes_init(password, (unsigned int)strlen(password), key, iv);

  printf("Key: "); for(i=0; i<EVP_aes_256_cbc()->key_len; ++i) { printf("%02x", key[i]); } printf("\n");
  printf("IV: "); for(i=0; i<EVP_aes_256_cbc()->iv_len; ++i) { printf("%02x", iv[i]); } printf("\n");

  len = encrypt(plaintext, (int)strlen(plaintext), key, iv, ciphertext);
  for(i=0;i<len;i++)
    printf("%02x",ciphertext[i]);
  printf("\n");

  len = decrypt(ciphertext, len, key, iv, plaintext);
  plaintext[len]='\0';
  printf("%s\n",plaintext);

  return 0;
}