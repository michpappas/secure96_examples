#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <secure96/s96at.h>

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof(arr[0]))

#define OPCODE_GENDIG		0x15
#define OPCODE_MAC		0x08
#define OPCODE_PRIVWRITE	0x46

#define SLOT_CONFIG_OFFSET	20
#define KEY_CONFIG_OFFSET	96

/* Sect 9.6 */
struct __attribute__((__packed__)) gendig_in {
	uint8_t data[32];
	uint8_t opcode;
	uint8_t param1;
	uint8_t param2[2];
	uint8_t sn_hi;
	uint8_t sn_lo[2];
	uint8_t zero[25];
	uint8_t temp_key[32];
};

/* Sect 9.14 */
struct __attribute__((__packed__)) auth_mac_in {
	uint8_t temp_key[32];
	uint8_t opcode;
	uint8_t param1;
	uint8_t param2[2];
	uint8_t sn_hi;
	uint8_t sn_lo[2];
	uint8_t zero[21];
	uint8_t padded_key[36];
};

static int atecc508a_read_config(struct s96at_desc *desc, uint8_t *buf)
{
	uint8_t ret;

	for (int i = 0; i < S96AT_ATECC508A_ZONE_CONFIG_NUM_BLOCKS; i++) {
		ret = s96at_read_config(desc, i, buf + i * S96AT_BLOCK_SIZE);
		if (ret != S96AT_STATUS_OK) {
			fprintf(stderr, "Failed to read config block %u\n", i);
			continue;
		}
	}
	return ret;
}

static int check_config(uint8_t *config_buf, uint8_t slot)
{
	int ret;
	uint8_t *slot_config;
	uint8_t *key_config;

	slot_config = config_buf + SLOT_CONFIG_OFFSET + 2 * slot;
	key_config = config_buf + KEY_CONFIG_OFFSET + 2 * slot;

	if (!(slot_config[0] & 0x80)) { /* IsSecret */
		fprintf(stderr, "Invalid config: SlotConfig.IsSecret = 0\n");
		ret = -1;
		goto out;
	}

	if (!(slot_config[1] & 0x40)) { /* PrivWrite */
		fprintf(stderr, "Invalid config: PrivWrite Forbidden\n");
		ret = -1;
		goto out;
	}

	if (!(key_config[0] & 0x01)) { /* Private */
		fprintf(stderr, "Invalid config: Not a private key\n");
		ret = -1;
		goto out;
	}
out:
	return ret;
}

static void sha256(uint8_t *msg, size_t len, uint8_t hash[S96AT_SHA_LEN])
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, msg, len);
	SHA256_Final(hash, &ctx);
}

static int read_EC_priv_from_pem(const char *file, uint8_t *buf)
{
	FILE *fp;
	const BIGNUM *priv;

	EVP_PKEY *pkey;
	EC_KEY *eckey;

	fp = fopen(file, "r");
	if (!fp) {
		perror("fopen");
		return -1;
	}

	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	if (!pkey) {
		fprintf(stderr, "Could not read Private Key\n");
		return -1;
	}

	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	if (!eckey) {
		fprintf(stderr, "Could not get EC_KEY\n");
		return -1;
	}

	priv = EC_KEY_get0_private_key(eckey);
	if (!priv) {
		fprintf(stderr, "Could not get Private Key\n");
		return -1;
	}

	BN_bn2bin(priv, buf);

	return 0;
}

static void notrandom(uint8_t *buf, size_t count)
{
	srand (time(NULL));
	for (int i = 0; i < count; i++)
		buf[i] = rand() % 0x100;
}

int main(int argc, char *argv[])
{
	uint8_t ret;
	struct s96at_desc desc;

	char *priv_key_file;

	uint8_t priv_key_slot;
	uint8_t parent_key_slot;

	uint8_t config_buf[S96AT_ATECC508A_ZONE_CONFIG_LEN] = {0};

	struct gendig_in digest_in;

	uint8_t priv[S96AT_ECC_PRIV_LEN];
	uint8_t num_in[S96AT_RANDOM_LEN];

	uint8_t temp_key[S96AT_SHA_LEN] = {0};
	uint8_t hashed_temp_key[S96AT_SHA_LEN];

	uint8_t padded_priv[36] = {0};
	uint8_t encrypted_priv[36] = {0};

	struct auth_mac_in mac_in;
	uint8_t auth_mac[S96AT_SHA_LEN];

	if (argc != 3) {
		fprintf(stderr, "Usage: %s slot priv.pem\n", argv[0]);
		return -1;
	}

	priv_key_slot = atoi(argv[1]);
	priv_key_file = argv[2];

	if (priv_key_slot > 15) {
		fprintf(stderr, "Invalid slot: %d\n", priv_key_slot);
		return -1;
	}

	ret = read_EC_priv_from_pem(priv_key_file, priv);
	if (ret)
		return ret;

	ret = s96at_init(S96AT_ATECC508A, S96AT_IO_I2C_LINUX, &desc);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not initialize descriptor\n");
		return ret;
	}

	while (s96at_wake(&desc) != S96AT_STATUS_READY) {};

	ret = atecc508a_read_config(&desc, config_buf);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not read device config\n");
		goto out;
	}

	parent_key_slot = config_buf[SLOT_CONFIG_OFFSET + priv_key_slot * 2 + 1] & 0x0f;
	ret = check_config(config_buf, priv_key_slot);
	if (ret)
		goto out;

	/* Before GenDig is executed, it is required that TempKey is
	 * populated using the Nonce command. We'll run Nonce in passthrough
	 * mode, and pass a series of pseudo-random bytes. Adjust this to
	 * your environment's security requirements.
	 */
	notrandom(num_in, ARRAY_LEN(num_in));
	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, num_in, NULL);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not generate nonce\n");
		goto out;
	}

	ret = s96at_gen_digest(&desc, S96AT_ZONE_DATA, parent_key_slot, NULL);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not generate digest\n");
		goto out;
	}

	/* Now compute the value of TempKey as set by Nonce and GenDigest.
	 * This will be our encryption key. The device will use it on its
	 * end to decrypt the EC Private Key.
	 *
	 * By convention, in our test configuration all bytes of each
	 * symmetric keys are set to the slot number, ie for Slot 0
	 * the key is all 0x00, for Slot 1 the key is all 0x11 etc.
	 * Adjust this to your own setup.
	 */
	memset(digest_in.data, parent_key_slot, 32);
	digest_in.opcode = OPCODE_GENDIG;
	digest_in.param1 = S96AT_ZONE_DATA;
	digest_in.param2[0] = parent_key_slot;
	digest_in.param2[1] = 0x00;
	digest_in.sn_hi = 0xee;
	digest_in.sn_lo[0] = 0x01;
	digest_in.sn_lo[1] = 0x23;
	memset(digest_in.zero, 0, 25);
	memcpy(digest_in.temp_key, num_in, 32);

	sha256((uint8_t *)&digest_in, sizeof(digest_in), temp_key);

	/* Encrypt the EC Private Key (Sect 9.14)
	 * The first 32 bytes are XORed with TempKey
	 * The remaining 4 bytes are XORed with SHA-256(TempKey)
	 */
	memcpy(padded_priv + 4, priv, 32);
	sha256(temp_key, 32, hashed_temp_key);
	for (int i = 0; i < 32; i++) {
		encrypted_priv[i] = padded_priv[i] ^ temp_key[i];
	}
	for (int i = 0; i < 4; i++) {
		encrypted_priv[32 + i] = padded_priv[32 + i] ^ hashed_temp_key[i];
	}

	/* Prepare the Authorizing MAC (Sect 9.14) */
	memcpy(mac_in.temp_key, temp_key, 32);
	mac_in.opcode = OPCODE_PRIVWRITE;
	mac_in.param1 = 1 << 6;
	mac_in.param2[0] = priv_key_slot;
	mac_in.param2[1] = 0;
	mac_in.sn_hi = 0xee;
	mac_in.sn_lo[0] = 0x01;
	mac_in.sn_lo[1] = 0x23;
	memset(mac_in.zero, 0 , 21);
	memcpy(mac_in.padded_key, padded_priv, 36);

	sha256((uint8_t *)&mac_in, 96, auth_mac);

	/* Send request to write encrypted key */
	ret = s96at_write_priv(&desc, priv_key_slot, encrypted_priv, auth_mac);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not write key: 0x%02x\n", ret);
		goto out;
	}

out:
	ret = s96at_cleanup(&desc);
	if (ret != S96AT_STATUS_OK)
		fprintf(stderr, "Could not cleanup\n");

	return ret;
}

