#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atecc508a.h>
#include <common.h>

extern uint8_t atecc508a_slot_config[32];
extern uint8_t atecc508a_key_config[32];
extern uint8_t atecc508a_data[1208];
extern uint8_t atecc508a_priv[128];
extern uint8_t atecc508a_otp[64];

uint16_t slot_get_length(uint8_t slot) {
	if (slot <= 7)
		return 36;
	else if (slot == 8)
		return 416;
	else
		return 72;
}

uint16_t slot_get_blocks(uint8_t slot) {
	if (slot <= 7)
		return 2;
	else if (slot == 8)
		return 13;
	else
		return 3;
}

int atecc508a_read_config(struct s96at_desc *desc, uint8_t *buf)
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

int atecc508a_personalize_config(struct s96at_desc *desc)
{
	uint8_t ret;
	uint16_t crc;
	uint8_t lock_config;
	uint8_t config_buf[S96AT_ATECC508A_ZONE_CONFIG_LEN] = { 0 };

	ret = s96at_get_lock_config(desc, &lock_config);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not get config lock status\n");
		goto out;
	}

	if (lock_config == S96AT_ZONE_LOCKED) {
		fprintf(stderr, "Configuration already locked, skipping\n");
		return S96AT_STATUS_OK;
	}

	/* Calculate the expected CRC: To lock the config zone, the CRC of
	 * the entire config zone is required. We read the current configuration
	 * and update the slot config and key config parts with the new values,
	 * before passing it to the CRC function.
	 */
	ret = atecc508a_read_config(desc, config_buf);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not read current config\n");
		goto out;
	}

	memcpy(config_buf + SLOT_CONFIG_OFFSET, atecc508a_slot_config,
	       ARRAY_LEN(atecc508a_slot_config));
	memcpy(config_buf + KEY_CONFIG_OFFSET, atecc508a_key_config,
	       ARRAY_LEN(atecc508a_key_config));
	crc = s96at_crc(config_buf, ARRAY_LEN(config_buf), 0);

	for (int i = 0; i < SLOT_CONFIG_NUM_WORDS; i++) {
		ret = s96at_write_config(desc, i + SLOT_CONFIG_START_WORD,
					 atecc508a_slot_config + i * 4);
		if (ret != S96AT_STATUS_OK) {
			fprintf(stderr, "Failed writing config slot %d\n", i);
			goto out;
		}
	}

	for (int i = 0; i < KEY_CONFIG_NUM_WORDS; i++) {
		ret = s96at_write_config(desc, i + KEY_CONFIG_START_WORD,
					 atecc508a_key_config + i * 4);
		if (ret != S96AT_STATUS_OK) {
			fprintf(stderr, "Failed writing config slot %d\n", i);
			goto out;
		}
	}

	ret = s96at_lock_zone(desc, S96AT_ZONE_CONFIG, crc);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not lock config\n");
		goto out;
	}
out:
	return ret;
}

int atecc508a_personalize_data(struct s96at_desc *desc)
{
	uint8_t ret;
	uint16_t crc;
	uint8_t lock_data;
	uint8_t slot[416]; /* Large enough to fit the largest slot size, ie slot 8 */
	struct s96at_slot_addr addr;
	uint8_t *ptr;

	ret = s96at_get_lock_data(desc, &lock_data);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not get config lock status\n");
		goto out;
	}

	if (lock_data == S96AT_ZONE_LOCKED) {
		fprintf(stderr, "Data / OTP already locked\n");
		goto out;
	}

	/* Write data */
	ptr = atecc508a_data;
	for (int i = 0; i < DATA_NUM_SLOTS; i++) {

		uint16_t slot_len = slot_get_length(i);
		uint16_t num_blocks = slot_get_blocks(i);

		memset(&addr, 0, sizeof(addr));
		addr.slot = i;

		memset(slot, 0, ARRAY_LEN(slot));
		memcpy(slot, ptr, slot_len);

		for (int j = 0; j < num_blocks; j++) {
			ret = s96at_write_data(desc, &addr, S96AT_FLAG_NONE,
					       slot + S96AT_BLOCK_SIZE * j,
					       S96AT_BLOCK_SIZE);
			if (ret != S96AT_STATUS_OK) {
				fprintf(stderr, "Failed writing data slot %d, block %d\n", i, j);
				goto out;
			}
			addr.block++;
		}
		ptr += slot_len;

		/* Force an idle-wake cycle every 4 slots to prevent the watchdog
		 * from putting the device to sleep during a write.
		 */
		if ((i + 1) % 4 == 0) {
			s96at_idle(desc);
			while (s96at_wake(desc) != S96AT_STATUS_READY) {};
		}
	}

	/* Write private keys */
	uint8_t *key = atecc508a_priv;
	for (int i = 0; i < DATA_NUM_SLOTS; i++) {
		if ((atecc508a_key_config[i * 2] & 0x01) == 0)
			continue;
		ret = s96at_write_priv(desc, i, key, NULL);
		if (ret != S96AT_STATUS_OK) {
			fprintf(stderr,"Failed writing private key into slot %d\n", i);
			goto out;
		}
		key += S96AT_ECC_PRIV_LEN;
	}

	/* OTP needs to be written in 2x 32byte blocks */
	for (int i = 0; i < 2; i++) {
		ret = s96at_write_otp(desc, i * 8, atecc508a_otp + i * 32, S96AT_BLOCK_SIZE);
		if (ret != S96AT_STATUS_OK) {
			fprintf(stderr, "Failed writing OTP word %d\n", i);
			goto out;
		}
	}

	/* Calculate the expected CRC: For the Data / OTP zones, the
	 * expected CRC is calculated over the concatenation of the
	 * contents of the two zones.
	 */
	crc = 0;
	ptr = atecc508a_data;
	for (int i = 0; i < DATA_NUM_SLOTS; i++) {
		uint16_t slot_len = slot_get_length(i);
		/* Skip slots containing private keys as they are not
		 * included in the CRC calculation. See Section 9.10
		 * of the ATECC508A datasheet.
		 */
		if ((atecc508a_key_config[i * 2] & 0x01) == 0) {
			crc = s96at_crc(ptr, slot_len, crc);
		}
		ptr += slot_len;
	}
	crc = s96at_crc(atecc508a_otp, ARRAY_LEN(atecc508a_otp), crc);

	ret = s96at_lock_zone(desc, S96AT_ZONE_DATA, crc);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not lock Data / OTP\n");
		goto out;
	}
out:
	return ret;
}

