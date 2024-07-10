/* main.c
 * Taylor Daniska
 *
 * Assumptions:
 *       The menu driven input is provided and must be used exactly
 *       as written.  A user can enter three commands, e.g.,:
 *            enc 0123456789abcdef 73
 *            dec f5fbc946ec523e08 73 F
 *            quit
 *       Encoding takes 16 hex digits for plaintext and 2 hex digits as the key
 *       Decoding takes 16 hex digits for ciphertext, 2 hex digits as the key,
 *            and one hex digit as the signature
 *
 * Tips: For a 64-bit OS, you can use unsigned long int to hold 64 bits
 *
 *       To print a long int use the %ld or %lx format
 *
 *       To set a 64-bit value use 1L instead of just 1.  This forces the
 *       compiler to use 64 instead of 32 bits.  This is needed within
 *       expressions using x as an unsigned long int such as "x & (1L <<  i)".
 *       If you use 1 instead of 1L (and i is an int not a long int), the
 *       compiler performns the << using 32 bits, and this is not what you want.
 *
 *       To get gdb to print in hex (x for hex) use
 *           p /x ciphertext
 *       to print in binary (t for two) use
 *           p /t ciphertext
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAXLINE 100
#define TEXTSIZE 16
#define KEWORDSIZE 2
#define SIGNATURESIZE 1

// function prototypes
void encode(char *, char *);
void decode(char *, char *, char);
void printbin(unsigned long int printingbit);

int main()
{
  char line[MAXLINE];
  char command[MAXLINE];
  char inputtext[MAXLINE];
  char inputkey[MAXLINE];
  char signature[MAXLINE];
  int  items;
  int i, invalid, invalidkey;

  printf("\nMP2: Vigenere cipher with signature\n");
  printf("Commands:\n\tenc 16-hex-digits 2-hex-digits (keyword)\n");
  printf("\tdec 16-hex-digits 2-hex-digits (keyword) 1-hex-digit (signature)\n\tquit\n");

  // each call to fgets collects one line of input and stores in line
  while (fgets(line, MAXLINE, stdin) != NULL) {
    items = sscanf(line, "%s%s%s%s", command, inputtext, inputkey, signature);
    if (items == 1 && strcmp(command, "quit") == 0) {
      break;
    }
    else if (items == 3 && strcmp(command, "enc") == 0) {
      // encoding
      if (strlen(inputtext) != TEXTSIZE || strlen(inputkey) != KEWORDSIZE) {
        printf("Invalid input to encoder: %s %s\n", inputtext, inputkey);
        printf("  Line was: %s\n", line);
      } 
      else {
        // verify that intput contains hex digits only
        for (i=0, invalid=0; i < strlen(inputtext) && !invalid; i++) {
          if (!isxdigit(inputtext[i]))
            invalid = 1;
        }
        for (i=0, invalidkey=0; i < strlen(inputkey) && !invalidkey; i++) {
          if (!isxdigit(inputkey[i]))
            invalidkey = 1;
        }
        if (invalid || invalidkey) {
          printf("Invalid characters in plaintext: %s or key: %s\n",
          inputtext, inputkey);
        }
        else {
          encode(inputtext, inputkey);
        }
      }
    }
    else if (items == 4 && strcmp(command, "dec") == 0) {
      // decoding
      if (strlen(inputtext) != TEXTSIZE || strlen(inputkey) != KEWORDSIZE || strlen(signature) != SIGNATURESIZE) {
        printf("Invalid input to decoder: %s %s %s\n", inputtext, inputkey, signature);
        printf("  Line was: %s\n", line);
      }
      else {
        // verify all digits are hex characters
        for (i=0, invalid=0; i < strlen(inputtext) && !invalid; i++) {
          if (!isxdigit(inputtext[i]))
            invalid = 1;
        }
        for (i=0, invalidkey=0; i < strlen(inputkey) && !invalidkey; i++) {
          if (!isxdigit(inputkey[i]))
            invalidkey = 1;
        }
        if (invalid || invalidkey || !isxdigit(signature[0])) {
          printf("Invalid decoder digits: %s or key: %s or signature %s\n", inputtext, inputkey, signature);
        }
        else {
          decode(inputtext, inputkey, signature[0]);
        }
      }
    } 
    else {
      printf("# :%s", line);
    }
  }
  printf("Goodbye\n");
  return 0;
}


/* encode: calculates the ciphertext and the signature
 *
 * input:  plaintext is exactly 16 hex digits
 *         keyword is exactly 2 hex digits
 *
 * assumptions: The input has already been tested to contain the correct number
 *              of valid hex digits
 *
 *              The keyword must be verified to be valid for a key.  If the
 *              keyword is not valid, return from the function without
 *              encoding the plaintext
 *
 * There is no return value, but the prints described below are required
 */
void encode(char plaintext[], char keyword[]) {
  // these definitions only work for a 64-bit architecture
  unsigned long int plainbits = 0;
  unsigned long int ciphertext = 0;
  unsigned long int keybit = 0;
  int signature = 0;
  int i =0,j=0;
  int nibble;
  int key = 0;
  int shift = 0;
  int keylength = 0;
  int keyleftover = 0;
  int dummy = -1;

  printf("\nEncoding plaintext: %s with key %s\n", plaintext, keyword);

  for(i=0; i<16; i++) {
    nibble = plaintext[i];
    if (nibble >= '0' && nibble <= '9') {
      nibble = nibble - '0';
    }
    else if (nibble >= 'a' && nibble <= 'f') {
      nibble = nibble - 'a' + 10;
    }
    else if (nibble >= 'A' && nibble <= 'F') {
      nibble = nibble - 'A' + 10;
    }
    plainbits = (plainbits << 4) | (nibble & 0xF);
  }
    
  printf("Plaintext as hex number: %016lx\n", plainbits);
  printbin(plainbits);
    
  for(i=0; i<2; i++) {
    nibble = keyword[i];
    if (nibble >= '0' && nibble <= '9') {
      nibble = nibble - '0';
    }
    else if (nibble >= 'a' && nibble <= 'f') {
      nibble = nibble - 'a' + 10;
    }
    else if (nibble >= 'A' && nibble <= 'F') {
      nibble = nibble - 'A' + 10;
    }
    key = (key << 4) | (nibble & 0xF);
  }
  for (i=8; i>=0; i--) {
    if ((key & ( 1 << i) ) >> i)
      break;
  }
  
  i++;
  keylength = i;
  nibble = key;
  dummy = key;

  if ((i <= 2) || (i > 8) || (key == 0x01) || (key == 0x03) || (key == 0x07) || (key == 0x0F) || (key == 0x1F) || (key == 0x3F) || (key == 0x7F) || (key == 0xFF)) {
    printf("keyword is invalid: %s, %x\n", keyword, dummy);
    return;
  }

  dummy = keylength;

  printf("Generate key from input: %s, Key length: %d Keyword: ", keyword, dummy);

  for (j=7; j>=0; j--) {
    printf("%d", (nibble & (1 << j )) >> j);
  }

  printf("\n");
  
  shift = 64 / keylength;
  keyleftover = 64 % keylength;
  keybit = key;

  for (i=shift; i>0; i--) {
    ciphertext = ciphertext | (keybit << ((keylength * i) + keyleftover - keylength)) ;
  }

  for (i=0; i<keyleftover; i++) {
    ciphertext = ciphertext | (0 << i);
  }
  
  ciphertext = ciphertext | (keybit >> (keylength - keyleftover));

  printbin(ciphertext);
  
  printf("Ciphertext\n");

  ciphertext = ciphertext ^ plainbits;

  printbin(ciphertext);
    
  int paritybit =0;
 
  unsigned long x = 1UL;

  for (i=1; i<64; i++) {
    if (((i % 2) == 0) || (i == 0))
      paritybit = paritybit + ((ciphertext & (x << i)) >> i);
  }

  paritybit = paritybit % 2;

  if(paritybit != 0) {
        dummy = 1;
  }
  else {
    dummy =0;
  }
  printf("B0 : %d\n", dummy);

  signature = signature | (dummy);

  paritybit = 0;
  for (i=0; i<64; i++) {
    if (((i % 3) == 0) || (i == 0)) {
      paritybit = paritybit + ((ciphertext & (x << i)) >> i);
    }
  }

  paritybit = paritybit % 2;

  if (paritybit != 0) {
    dummy = 1;
  }
  else {
    dummy =0;
  }

  printf("B1 : %d\n", dummy);
  signature = signature | (dummy << 1);
  paritybit = 0;
  for (i=12; i<=25; i++) {
    paritybit = paritybit + ((ciphertext & (x << i)) >> i);
  }

  paritybit = paritybit % 2;

  if (paritybit > 0) {
    dummy = 1;
  }
  else {
    dummy =0;
  }

  printf("B2 : %d\n", dummy);
  signature = signature | (dummy << 2);
  paritybit = 0;
  for (i=0; i<64; i++) {
    if (i==0 || i==1 || i==3 || i==7 || i==15 || i==31 || i==63)
      paritybit = paritybit + ((ciphertext & (x << i)) >> i);
  }

  paritybit = paritybit % 2;

  if (paritybit > 0) {
    dummy = 1;
  }
  else {
    dummy =0;
  }

  printf("B3 : %d\n", dummy);
  signature = signature | (dummy << 3);

  printf("Ciphertext with signature: %16lx  %s %X\n\n", ciphertext, keyword, signature);
}

/* decode: checks the keword and signature and prints the plaintext
 *
 * input: ciphertext as 16 hex digits
 *        keyword as 2 hex digits
 *        signature as 1 hex character
 *
 * assumptions: The keyword must be verified to be valid for a key.  If the
 *              keyword is not valid, return from the function without
 *              checking the signature or decoding the ciphertext
 *
 *              Next, the signature must be verified to be valid.  If not, return
 *              from the function without decoding the ciphertext
 *
 *              This function assumes that the ciphertext, keyword, and
 *              signature have already been verified to contain the
 *              correct number of hex digits and no incorrect digits.
 *
 *  The prints included below provide the format required for the output.
 *
 */
void decode(char ciphertext[], char keyword[], char signature) {
  printf("\nDecoding: %s with signature %c and key: %s\n", ciphertext, signature, keyword);

  unsigned long int cipherbits = 0;
  unsigned long int plaintext = 0;
  unsigned long int keybit = 0;
  
  int dummy = -1;
  int signature_d = 0;
  int signature_e = 0;
  int nibble = 0;
  int i,j;
  int key = 0;
  int keylength;
  int shift;
  int keyleftover;
  
  for(i=0; i<2; i++) {
    nibble = keyword[i];
    if (nibble >= '0' && nibble <= '9') {
      nibble = nibble - '0';
    }
    else if (nibble >= 'a' && nibble <= 'f') {
      nibble = nibble - 'a' + 10;
    }
    else if (nibble >= 'A' && nibble <= 'F') {
      nibble = nibble - 'A' + 10;
    }
    key = (key << 4) | (nibble & 0xF);
  }

  nibble = key;

  for (i=8; i>=0; i--) {
    if ((key & ( 1 << i) ) >> i)
      break;
  }
  
  i++;
  keylength = i;
  dummy = key;

  if ((i <= 2) || (i > 8) || (key == 0x01) || (key == 0x03) || (key == 0x07) || (key == 0x0F) || (key == 0x1F) || (key == 0x3F) || (key == 0x7F) || (key == 0xFF)) {
    printf("keyword is invalid: %s, %x\n", keyword, dummy);
    return;
  }
  
  dummy = i;
    
  printf("Generate key from input: %s, Key length: %d Keyword: ", keyword, dummy);
  for (j=7; j>=0; j--) {
    printf("%d", (nibble & (1 << j )) >> j);
  }

  shift = 64 / keylength;
  keyleftover = 64 % keylength;
  keybit = key;
  unsigned long int full_key = 0;

  for (i=shift; i>0; i--) {
    full_key = full_key | (keybit << ((keylength * i) + keyleftover - keylength)) ;
  }

  for (i=0; i<keyleftover; i++) {
    full_key = full_key | (0 << i);
  }

  full_key = full_key | (keybit >> (keylength - keyleftover));

  printf("\n");

  for(i=0; i<16; i++) {
    nibble = ciphertext[i];
    if (nibble >= '0' && nibble <= '9') {
      nibble = nibble - '0';
    }
    else if (nibble >= 'a' && nibble <= 'f') {
      nibble = nibble - 'a' + 10;
    }
    else if (nibble >= 'A' && nibble <= 'F') {
      nibble = nibble - 'A' + 10;
    }
    cipherbits = (cipherbits << 4) | (nibble & 0xF);
  }

  printbin(full_key);
  
  printf("Cipher as hex number: %lx\n", cipherbits);
  printbin(cipherbits);

  int paritybit =0;
  unsigned long x = 1UL;

  for (i=1; i<64; i++) {
    if (((i % 2) == 0) || (i == 0))
      paritybit = paritybit + ((cipherbits & (x << i)) >> i);
  }

  paritybit = paritybit % 2;

  if (paritybit != 0) {
    dummy = 1;
  }
  else {
    dummy =0;
  }
  printf("B0 : %d\n", dummy);

  signature_d = signature_d | (dummy);

  paritybit = 0;
  for (i=0; i<64; i++) {
    if (((i % 3) == 0) || (i == 0)) {
      paritybit = paritybit + ((cipherbits & (x << i)) >> i);
    }
  }

  paritybit = paritybit % 2;

  if (paritybit != 0) {
    dummy = 1;
  }
  else {
    dummy =0;
  }

  printf("B1 : %d\n", dummy);
  signature_d = signature_d | (dummy << 1);
  paritybit = 0;
  for (i=12; i<=25; i++) {
    paritybit = paritybit + ((cipherbits & (x << i)) >> i);
  }

  paritybit = paritybit % 2;

  if (paritybit > 0) {
    dummy = 1;
    }
  else {
      dummy =0;
  }

  printf("B2 : %d\n", dummy);
  signature_d = signature_d | (dummy << 2);
  paritybit = 0;
  for (i=0; i<64; i++) {
    if (i==0 || i==1 || i==3 || i==7 || i==15 || i==31 || i==63)
      paritybit = paritybit + ((cipherbits & (x << i)) >> i);
  }

  paritybit = paritybit % 2;

  if (paritybit > 0) {
    dummy = 1;
  }
  else {
    dummy =0;
  }

  printf("B3 : %d\n", dummy);
  signature_d = signature_d | (dummy << 3);

  nibble = signature;
  if (nibble >= '0' && nibble <= '9') {
    nibble = nibble - '0';
  }
  else if (nibble >= 'a' && nibble <= 'f') {
    nibble = nibble - 'a' + 10;
  }
  else if (nibble >= 'A' && nibble <= 'F') {
    nibble = nibble - 'A' + 10;
  }
  signature_e = (signature_e << 4) | (nibble & 0xF);

  if (signature_d != signature_e) {
    printf("Message is not from a trusted source!\n");
    return;
  }

  plaintext = full_key ^ cipherbits;

  printf("Plaintext\n");
  printbin(plaintext);
  
  printf(" Original plaintext: %016lX\n\n", plaintext);
}

void printbin(unsigned long int printingbit) {
  int i=0,j=0;

  printf(" ");
  int holder = 0;
  
  for (j=63,i=1; j>=0; j--,i++) {
    holder = ((printingbit >> j) & 0x1);
    printf("%d", holder);
    if (i == 4) {
      i = 0;
      printf(" ");
    }
  }
  printf("\n    ");
  for(i=16; i>=1; i--) {
    holder = ((printingbit >> (i * 4 - 4)) & 0xF);
    printf("%01x    ", holder);
  }
  printf("\n");
}
