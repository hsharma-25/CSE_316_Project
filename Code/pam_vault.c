#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#define VAULT_FILE "password_vault.bin"
#define KEY_FILE "vault_key.bin"
static int decrypt_password(char *decrypted_password) {
unsigned char key[crypto_secretbox_KEYBYTES];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char ciphertext[256];
unsigned char decrypted[256];
FILE *key_file = fopen(KEY_FILE, "rb");
if (key_file == NULL) {
return PAM_AUTH_ERR; // Key missing
}
fread(key, 1, sizeof key, key_file);
fclose(key_file);
FILE *vault = fopen(VAULT_FILE, "rb");
if (vault == NULL) {
return PAM_AUTH_ERR; // Vault missing
}
fread(nonce, 1, sizeof nonce, vault);
fread(ciphertext, 1, sizeof ciphertext, vault);
fclose(vault);
if (crypto_secretbox_open_easy(decrypted, ciphertext, sizeof ciphertext, nonce, key) != 0) {
return PAM_AUTH_ERR; // Decryption failed
}
strcpy(decrypted_password, (char *)decrypted);
return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user_password;
char stored_password[256];
if (pam_get_authtok(pamh, PAM_AUTHTOK, &user_password, NULL) != PAM_SUCCESS) {
syslog(LOG_AUTH | LOG_WARNING, "Failed to get user password input");
return PAM_AUTH_ERR;
}
if (decrypt_password(stored_password) != PAM_SUCCESS) {
return PAM_AUTH_ERR;
}
if (strcmp(user_password, stored_password) == 0) {
syslog(LOG_AUTH | LOG_INFO, "User authentication successful");
return PAM_SUCCESS;
} else {
syslog(LOG_AUTH | LOG_WARNING, "User authentication failed - password mismatch");
return PAM_AUTH_ERR;
}
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
return PAM_SUCCESS;
}
