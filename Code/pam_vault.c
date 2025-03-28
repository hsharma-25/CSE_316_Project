#include <time.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#define MAX_FAILED_ATTEMPTS 5 // Lockout threshold
#define LOCKOUT_DURATION 300 // Lockout period in seconds (5 minutes)
#define LOCKOUT_FILE "/var/lib/pam_vault/lockout.db"
#define HMAC_KEY "super_secret_hmac_key" // Store securely!
#define VAULT_FILE "password_vault.bin"
#define KEY_FILE "vault_key.bin"
#define PASSWORD_FILE "/var/lib/pam_vault/passwords.db"
#define HASH_SIZE crypto_pwhash_STRBYTES

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
void encrypt_and_log(const char *message) {
unsigned char key[crypto_secretbox_KEYBYTES];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char ciphertext[crypto_secretbox_MACBYTES + strlen(message)];
// Generate a random key (store securely in practice!)
randombytes_buf(key, sizeof key);
randombytes_buf(nonce, sizeof nonce);
crypto_secretbox_easy(ciphertext, (unsigned char *)message, strlen(message), nonce, key);
FILE *file = fopen("/var/log/pam_vault_encrypted.log", "ab");
if (file) {
fwrite(nonce, sizeof nonce, 1, file);
fwrite(ciphertext, sizeof ciphertext, 1, file);
fclose(file);
}
}
void generate_hmac(const unsigned char *data, size_t data_len, unsigned char *hmac_output) {
unsigned int len;
HMAC(EVP_sha256(), HMAC_KEY, strlen(HMAC_KEY), data, data_len, hmac_output, &len);
}
int verify_hmac(const unsigned char *data, size_t data_len, const unsigned char *expected_hmac) {
unsigned char computed_hmac[EVP_MAX_MD_SIZE];
generate_hmac(data, data_len, computed_hmac);
return memcmp(computed_hmac, expected_hmac, EVP_MD_size(EVP_sha256())) == 0;
}
void log_failed_attempt(const char *username) {
FILE *file = fopen(LOCKOUT_FILE, "a");
if (!file) return;
time_t now = time(NULL);
fprintf(file, "%s %ld\n", username, now);
fclose(file);
}
int is_user_locked_out(const char *username) {
FILE *file = fopen(LOCKOUT_FILE, "r");
if (!file) return 0; // No file means no lockouts
time_t now = time(NULL);
int failed_count = 0;
time_t last_attempt_time = 0;
char stored_user[256];
time_t attempt_time;
// Clean old entries into a temporary file
FILE *temp = fopen("/var/lib/pam_vault/temp.db", "w");
while (fscanf(file, "%s %ld", stored_user, &attempt_time) != EOF) {
if (attempt_time > now - LOCKOUT_DURATION) {
fprintf(temp, "%s %ld\n", stored_user, attempt_time);
if (strcmp(stored_user, username) == 0) {
failed_count++;
last_attempt_time = attempt_time;
}
}
}
fclose(file);
fclose(temp);
rename("/var/lib/pam_vault/temp.db", LOCKOUT_FILE);
if (failed_count >= MAX_FAILED_ATTEMPTS) {
if (now - last_attempt_time < LOCKOUT_DURATION) {
return 1; // User is locked out
}
}
return 0;
}
void hash_password(const char *password, char *hashed_password) {
if (sodium_init() < 0) {
fprintf(stderr, "Failed to initialize libsodium\n");
exit(1);
}
if (crypto_pwhash_str(hashed_password, password, strlen(password),
crypto_pwhash_OPSLIMIT_INTERACTIVE,
crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
fprintf(stderr, "Password hashing failed\n");
exit(1);
}
}
int verify_password(const char *password, const char *hashed_password) {
return crypto_pwhash_str_verify(hashed_password, password, strlen(password));
}
void register_user(const char *username, const char *password) {
char hashed_password[HASH_SIZE];
hash_password(password, hashed_password);
FILE *file = fopen(PASSWORD_FILE, "a");
if (!file) {
fprintf(stderr, "Error opening password file\n");
return;
}
fprintf(file, "%s %s\n", username, hashed_password);
fclose(file);
}
int authenticate_user(const char *username, const char *password) {
FILE *file = fopen(PASSWORD_FILE, "r");
if (!file) return PAM_AUTH_ERR;
char stored_username[256];
char stored_hash[HASH_SIZE];
while (fscanf(file, "%s %s", stored_username, stored_hash) != EOF) {
if (strcmp(username, stored_username) == 0) {
fclose(file);
return verify_password(password, stored_hash) == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
}
}
fclose(file);
return PAM_AUTH_ERR;
}
