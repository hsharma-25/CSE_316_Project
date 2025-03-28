#include <sodium.h>
#include <stdio.h>
#include <string.h>
#define KEY_FILE "vault_key.bin"
#define VAULT_FILE "password_vault.bin"
void generate_key() {
unsigned char key[crypto_secretbox_KEYBYTES];
randombytes_buf(key, sizeof key);
FILE *key_file = fopen(KEY_FILE, "wb");
if (key_file == NULL) {
perror("Error creating key file");
return;
}
fwrite(key, 1, sizeof key, key_file);
fclose(key_file);
printf("Encryption key generated and saved.\n");
}
void encrypt_password(const char *password) {
unsigned char key[crypto_secretbox_KEYBYTES];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char ciphertext[crypto_secretbox_MACBYTES + strlen(password)];
FILE *key_file = fopen(KEY_FILE, "rb");
if (key_file == NULL) {
printf("Key file not found! Generate a key first.\n");
return;
}
fread(key, 1, sizeof key, key_file);
fclose(key_file);
randombytes_buf(nonce, sizeof nonce);
crypto_secretbox_easy(ciphertext, (unsigned char *)password, strlen(password), nonce, key);
FILE *vault = fopen(VAULT_FILE, "wb");
if (vault == NULL) {
perror("Error opening vault file");
return;
}
fwrite(nonce, 1, sizeof nonce, vault);
fwrite(ciphertext, 1, sizeof ciphertext, vault);
fclose(vault);
printf("Password encrypted and stored successfully.\n");
}
void decrypt_password() {
unsigned char key[crypto_secretbox_KEYBYTES];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char ciphertext[256];
unsigned char decrypted[256];
FILE *key_file = fopen(KEY_FILE, "rb");
if (key_file == NULL) {
printf("Key file missing! Cannot decrypt.\n");
return;
}
fread(key, 1, sizeof key, key_file);
fclose(key_file);
FILE *vault = fopen(VAULT_FILE, "rb");
if (vault == NULL) {
printf("Vault file missing! Cannot decrypt.\n");
return;
}
fread(nonce, 1, sizeof nonce, vault);
fread(ciphertext, 1, sizeof ciphertext, vault);
fclose(vault);
if (crypto_secretbox_open_easy(decrypted, ciphertext, sizeof ciphertext, nonce, key) != 0) {
printf("Decryption failed! Invalid key or data.\n");
return;
}
printf("Decrypted Password: %s\n", decrypted);
}
int main(int argc, char *argv[]) {
if (sodium_init() < 0) {
printf("Libsodium initialization failed!\n");
return 1;
}
if (argc != 2) {
printf("Usage: %s [generate|encrypt|decrypt]\n", argv[0]);
return 1;
}
if (strcmp(argv[1], "generate") == 0) {
generate_key();
} else if (strcmp(argv[1], "encrypt") == 0) {
char password[100];
printf("Enter password to encrypt: ");
scanf("%99s", password);
encrypt_password(password);
} else if (strcmp(argv[1], "decrypt") == 0) {
decrypt_password();
} else {
printf("Invalid command! Use generate, encrypt, or decrypt.\n");
}
return 0;
}
