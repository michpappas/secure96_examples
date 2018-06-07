#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <secure96/s96at.h>

#include <atsha204a.h>
#include <common.h>

extern uint8_t atsha204a_slot_config[32];
extern uint8_t atsha204a_data[512];
extern uint8_t atsha204a_otp[64];

int atsha204a_read_config(struct s96at_desc *desc, uint8_t *buf)
{
	uint8_t ret;

	for (int i = 0; i < S96AT_ATSHA204A_ZONE_CONFIG_NUM_WORDS; i++) {
		ret = s96at_read_config(desc, i, buf + i * S96AT_WORD_SIZE);
		if (ret != S96AT_STATUS_OK) {
			fprintf(stderr, "Failed to read config word %u\n", i);
			continue;
		}
	}
	return ret;
}

int atsha204a_personalize_config(struct s96at_desc *desc)
{
	uint8_t ret;
	uint16_t crc;
	uint8_t lock_config;
	uint8_t config_buf[ZONE_CONFIG_LEN_MAX] = { 0 };

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
	 * and update the slot config part with the new values before passing it
	 * to the CRC function.
	 */
	//ret = read_config(desc, dev, config_buf);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not read current config\n");
		goto out;
	}

	memcpy(config_buf + SLOT_CONFIG_OFFSET, atsha204a_slot_config,
	       ARRAY_LEN(atsha204a_slot_config));
	crc = s96at_crc(config_buf, ARRAY_LEN(config_buf), 0);
/*
	for (int i = 0; i < SLOT_CONFIG_NUM_WORDS; i++) {
		ret = s96at_write_config(desc, i + SLOT_CONFIG_START_WORD,
					 atsha204a_slot_config + i * 4);
		if (ret != S96AT_STATUS_OK) {
			fprintf(stderr, "Failed writing config slot %d\n", i);
			goto out;
		}
	}
*/
	ret = s96at_lock_zone(desc, S96AT_ZONE_CONFIG, crc);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not lock config\n");
		goto out;
	}
out:
	return ret;
}

int atsha204a_personalize_data(struct s96at_desc *desc)
{
	uint8_t ret;
	uint16_t crc;
	uint8_t lock_data;
	struct s96at_slot_addr addr = {0};

	ret = s96at_get_lock_data(desc, &lock_data);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not get config lock status\n");
		goto out;
	}

	if (lock_data == S96AT_ZONE_LOCKED) {
		fprintf(stderr, "Data / OTP already locked\n");
		goto out;
	}

	for (int i = 0; i < DATA_NUM_SLOTS; i++) {
		addr.slot = i;
		ret = s96at_write_data(desc, &addr, S96AT_FLAG_NONE,
				       atsha204a_data + (i * 32), 32);
		if (ret != S96AT_STATUS_OK) {
			fprintf(stderr, "Failed writing data slot %d\n", i);
			break;
		}
	}

	for (int i = 0; i < 2; i++) {
		ret = s96at_write_otp(desc, i * 8, atsha204a_otp + i * 32, 32);
		if (ret != S96AT_STATUS_OK) {
			fprintf(stderr, "Failed writing OTP word %d\n", i);
			break;
		}
	}

	/* Calculate the expected CRC: For the Data / OTP zones, the
	 * expected CRC is calculated over the concatenation of the
	 * contents of the two zones.
	 */
	crc = s96at_crc(atsha204a_data, ARRAY_LEN(atsha204a_data), 0);
	crc = s96at_crc(atsha204a_otp, ARRAY_LEN(atsha204a_otp), crc);

	ret = s96at_lock_zone(desc, S96AT_ZONE_DATA, crc);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not lock Data / OTP\n");
		goto out;
	}

out:
	return ret;
}

