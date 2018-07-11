#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <secure96/s96at.h>

#define VALIDATE	0
#define INVALIDATE	1

#define SLOT_CONFIG_OFFSET	20
#define KEY_CONFIG_OFFSET	96

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof(arr[0]))

/* Sect 9.20 */
struct __attribute__((__packed__)) verify_msg {
	uint8_t mode;
	uint8_t key_id[2];	/* ParentPriv slot */
	uint8_t slot_config[2];	/* SlotConfig[Pub] */
	uint8_t key_config[2];	/* KeyConfig[Pub] */
	uint8_t temp_key_flags;
	uint8_t zeros[2];
	uint8_t sn4[4];		/* SN[4:7] or zero */
	uint8_t sn2[2];		/* SN[2:3] or zero */
	uint8_t slot_locked;	/* Config.SlotLocked[Pub] */
	uint8_t pub_key_valid;	/* 0 if pub key is currenlty invalid, 1 if currently valid */
	uint8_t zero;
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

	uint8_t action;

	uint8_t slot_pub;
	uint8_t slot_parent_priv;
	uint8_t *slot_config_pub;
	uint8_t *key_config_pub;
	uint8_t *key_config_parent_priv;

	uint8_t state[2];

	uint8_t config_buf[S96AT_ATECC508A_ZONE_CONFIG_LEN] = {0};

	uint8_t num_in[S96AT_RANDOM_LEN] = {0};

	struct s96at_ecdsa_sig sig;
	uint32_t sign_flags = S96AT_FLAG_NONE;

	struct verify_msg message;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s [validate|invalidate] slot_pub slot_parent_priv\n", argv[0]);
		return -1;
	}

	if (!strcmp(argv[1], "validate")) {
		action = VALIDATE;
	} else if (!strcmp(argv[1], "invalidate")) {
		action = INVALIDATE;
	} else {
		fprintf(stderr, "Invalid action: %s\n", argv[1]);
		return -1;
	}

	slot_pub = atoi(argv[2]);
	slot_parent_priv = atoi(argv[3]);

	if (slot_pub < 8 || slot_pub > 15) {
		fprintf(stderr, "Invalid slot: %d\n", slot_parent_priv);
		return -1;
	}

	if (slot_parent_priv > 15) {
		fprintf(stderr, "Invalid slot: %d\n", slot_parent_priv);
		return -1;
	}

	if (action == INVALIDATE)
		sign_flags |= S96AT_FLAG_INVALIDATE;

	ret = s96at_init(S96AT_ATECC508A, S96AT_IO_I2C_LINUX, &desc);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not initialize descriptor\n");
		return ret;
	}

	while (s96at_wake(&desc) != S96AT_STATUS_READY) {};

	ret = atecc508a_read_config(&desc, config_buf);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not read device config\n");
		ret = -1;
		goto out;
	}

	slot_config_pub = config_buf + SLOT_CONFIG_OFFSET + 2 * slot_pub;
	key_config_pub = config_buf + KEY_CONFIG_OFFSET + 2 * slot_pub;

	key_config_parent_priv = config_buf + KEY_CONFIG_OFFSET + 2 * slot_parent_priv;

	if (key_config_pub[0] & 0x01) {
		fprintf(stderr, "Not a public key\n");
		ret = S96AT_STATUS_BAD_PARAMETERS;
		goto out;
	}

	if (!(key_config_parent_priv[0] & 0x01)) {
		fprintf(stderr, "Not a private key\n");
		ret = S96AT_STATUS_BAD_PARAMETERS;
		goto out;
	}

	/* ---- SIGN SIDE ---- */

	/* Before GenDig is executed, it is required that TempKey is
	 * populated using the Nonce command. We'll run Nonce in passthrough
	 * mode, and pass a series of pseudo-random bytes. Adjust this to
	 * your environment's security requirements.
	 */
	notrandom(num_in, ARRAY_LEN(num_in));

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, num_in, NULL);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Nonce failed\n");
		goto out;
	}

	ret = s96at_gen_key(&desc, S96AT_GENKEY_MODE_DIGEST, slot_pub, NULL);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "GenKey failed\n");
		goto out;
	}

	ret = s96at_sign(&desc, S96AT_SIGN_MODE_INTERNAL, slot_parent_priv,
			 sign_flags, &sig);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Sign failed\n");
		goto out;
	}

	/* ---- VERIFY SIDE ---- */
	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, num_in, NULL);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Nonce failed\n");
		goto out;
	}
	ret = s96at_gen_key(&desc, S96AT_GENKEY_MODE_DIGEST, slot_pub, NULL);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "GenKey failed\n");
		goto out;
	}

	/* Prepare message to be passed to OtherData */
	ret = s96at_get_state(&desc, state);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Info failed\n");
		goto out;
	}

	memset(&message, 0, sizeof(struct verify_msg));
	message.mode = (action == VALIDATE) ? 0x00 : 0x01;
	message.key_id[0] = slot_parent_priv;
	message.slot_config[0] = slot_config_pub[0];
	message.slot_config[1] = slot_config_pub[1];
	message.key_config[0] = key_config_pub[0];
	message.key_config[1] = key_config_pub[1];
	message.temp_key_flags = state[0];
	message.slot_locked = 0x01; /* Read this from Config */
	message.pub_key_valid = (action == VALIDATE) ? 0 : 1;

	if (action == VALIDATE)
		ret = s96at_verify_key(&desc, S96AT_VERIFY_KEY_MODE_VALIDATE, &sig,
				       slot_pub, (uint8_t *)&message);
	else
		ret = s96at_verify_key(&desc, S96AT_VERIFY_KEY_MODE_INVALIDATE, &sig,
				       slot_pub, (uint8_t *)&message);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Verify failed\n");
		goto out;
	}

out:
	ret = s96at_cleanup(&desc);
	if (ret != S96AT_STATUS_OK)
		fprintf(stderr, "Could not cleanup\n");

	return ret;
}

