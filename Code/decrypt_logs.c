#include <stdio.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#define LOG_FILE "/var/log/pam_vault_encrypted.log"
void decrypt_log(const unsigned char *key) {
FILE *file = fopen(LOG_FILE, "rb");
if (!file) {
printf("Error: Cannot open log file.\n");
return;
}
fseek(file, 0, SEEK_END);
long file_size = ftell(file);
rewind(file);
while (ftell(file) < file_size) {
unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char ciphertext[512]; // Assuming max log entry size
unsigned char decrypted[512];
fread(nonce, sizeof nonce, 1, file);
fread(ciphertext, sizeof ciphertext, 1, file);
if (crypto_secretbox_open_easy(decrypted, ciphertext, sizeof ciphertext, nonce, key) != 0) {
printf("Error: Decryption failed.\n");
} else {
printf("Decrypted Log: %s\n", decrypted);
}
}
fclose(file);
}
int main() {
if (getuid() != 0) {
printf("Error: Run this program as root (use sudo).\n");
return 1;
}
unsigned char key[crypto_secretbox_KEYBYTES];
printf("Enter decryption key (in hex, 32 bytes): ");
for (int i = 0; i < crypto_secretbox_KEYBYTES; i++) {
scanf("%2hhx", &key[i]);
}
decrypt_log(key);
return 0;
}
