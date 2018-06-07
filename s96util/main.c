/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <secure96/s96at.h>

#include <atecc508a.h>
#include <atsha204a.h>
#include <common.h>

static void usage(char *fname)
{
	fprintf(stderr, "Usage: %s <device> <option>\n", fname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Available devices:\n");
	fprintf(stderr, "  atsha		atsha204a\n");
	fprintf(stderr, "  atecc		atecc508a\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Available options:\n");
	fprintf(stderr, "  -i, --info		Display device info\n");
	fprintf(stderr, "  -d, --dump-config	Dump config zone\n");
	fprintf(stderr, "  -p, --personalize	Write config and data\n");
	fprintf(stderr, "  -h, --help		Display this message\n");
	fprintf(stderr, "  -v, --version	Display version\n");
	fprintf(stderr, "\n");
}

static int confirm()
{
	char resp[4];
	int confirm = 1;

	do {
		printf("Continue? [yN] ");
		fgets(resp, sizeof(resp), stdin);
		if (resp[0] == 'y' || resp[0] == 'Y') { /* yolo works here too */
			confirm = 0;
			break;
		} else if (resp[0] == 'n' || resp[0] == 'N' || resp[0] == '\n') {
			confirm = 1;
			break;
		}
		printf("Invalid option. ");
	} while(1);

	return confirm;
}

static char *otpmode2str(uint8_t mode)
{
	switch (mode) {
	case 0x00:
		return "Legacy";
	case 0x55:
		return "Consumption";
	case 0xAA:
		return "Readonly";
	default:
		return "Unknown\n";
	}
}

int main(int argc, char *argv[])
{
	uint8_t ret;
	uint8_t dev;
	struct s96at_desc desc;

	uint8_t otp_mode;
	uint8_t lock_config;
	uint8_t lock_data;
	uint8_t devrev[S96AT_DEVREV_LEN] = { 0 };
	uint8_t sn[S96AT_SERIAL_NUMBER_LEN] = { 0 };
	uint8_t config_buf[ZONE_CONFIG_LEN_MAX] = { 0 };

	int opt;
	int opt_idx = 0;
	static struct option long_opts[] = {
		{"dump-config",  no_argument, 0, 'd'},
		{"personalize",  no_argument, 0, 'p'},
		{"help",         no_argument, 0, 'h'},
		{"info",         no_argument, 0, 'i'},
		{"version",      no_argument, 0, 'v'},
		{0, 0, 0, 0}
	};

	if (argc < 3) {
		usage(argv[0]);
		return -1;
	}

	if (!strcmp(argv[1], "atsha")) {
		dev = S96AT_ATSHA204A;
	} else if (!strcmp(argv[1], "atecc")) {
		dev = S96AT_ATECC508A;
	} else {
		fprintf(stderr, "Bad device %s\n", argv[1]);
		return -1;
	}

	ret = s96at_init(dev, S96AT_IO_I2C_LINUX, &desc);
	if (ret != S96AT_STATUS_OK) {
		fprintf(stderr, "Could not initialize a descriptor\n");
		return ret;
	}

	while (1) {
		opt_idx = 0;
		opt = getopt_long(argc, argv, "idphv", long_opts, &opt_idx);

		if (opt == -1) /* End of options. */
			break;

		switch (opt) {
		case 'i':
			while (s96at_wake(&desc) != S96AT_STATUS_READY) {};

			ret = s96at_get_devrev(&desc, devrev);
			if (ret != S96AT_STATUS_OK) {
				fprintf(stderr, "Failed to get device revision\n");
				goto out;
			}

			ret = s96at_get_serialnbr(&desc, sn);
			if (ret != S96AT_STATUS_OK) {
				fprintf(stderr, "Failed to get SN\n");
				goto out;
			}

			ret = s96at_get_otp_mode(&desc, &otp_mode);
			if (ret != S96AT_STATUS_OK) {
				fprintf(stderr, "Failed to get OTP mode\n");
				goto out;
			}

			ret = s96at_get_lock_config(&desc, &lock_config);
			if (ret != S96AT_STATUS_OK) {
				fprintf(stderr, "Failed to get config lock status\n");
				goto out;
			}

			ret = s96at_get_lock_data(&desc, &lock_data);
			if (ret != S96AT_STATUS_OK) {
				fprintf(stderr, "Failed to get LockData\n");
				goto out;
			}

#if 0
			printf("ATSHA204A on %s @ addr 0x%x\n", I2C_DEVICE, ATSHA204A_ADDR);
#endif
			printf("Device Revision:    %02x%02x%02x%02x\n",
				devrev[0], devrev[1], devrev[2], devrev[3]);
			printf("Serial Number:      %02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
				sn[0], sn[1], sn[2], sn[3], sn[4], sn[5], sn[6], sn[7], sn[8]);
			printf("Config Zone locked: %s\n",
				lock_config == S96AT_ZONE_UNLOCKED ? "No" : "Yes");
			printf("Data Zone locked:   %s\n",
				lock_data == S96AT_ZONE_UNLOCKED ? "No" : "Yes");
			printf("OTP mode:           %s\n", otpmode2str(otp_mode));
			break;
		case 'd':
			while (s96at_wake(&desc) != S96AT_STATUS_READY) {};

			if (dev == S96AT_ATECC508A)
				ret = atecc508a_read_config(&desc, config_buf);
			else
				ret = atsha204a_read_config(&desc, config_buf);
			if (ret != S96AT_STATUS_OK) {
				fprintf(stderr, "Could not read config\n");
				goto out;
			}

			for (int i = 0; i < ARRAY_LEN(config_buf); i ++) {
				printf("%c", config_buf[i]);
			}
			break;
		case 'p':
			printf("WARNING: Personalizing the device is an one-time operation! ");
			if (confirm())
				goto out;

			while (s96at_wake(&desc) != S96AT_STATUS_READY) {};
#if 0
			if (dev == S96AT_ATECC508A)
				ret = atecc508a_personalize_config(&desc);
			else
				ret = atsha204a_personalize_config(&desc);
			if (ret != S96AT_STATUS_OK) {
				fprintf(stderr, "Personalization failed\n");
				goto out;
			}
#endif
			if (dev == S96AT_ATECC508A)
				ret = atecc508a_personalize_data(&desc);
			else
				ret = atsha204a_personalize_data(&desc);
			if (ret != S96AT_STATUS_OK) {
				fprintf(stderr, "Personalization failed\n");
				goto out;
			}
			printf("Done\n");
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'v':
			printf("%s version: %s\n", PROJECT_NAME, PROJECT_VERSION);
			printf("libs96at version:   %s\n", S96AT_VERSION);
		default:
			break;
		}
	}
out:
	ret = s96at_cleanup(&desc);
	if (ret != S96AT_STATUS_OK)
		fprintf(stderr, "Could not cleanup\n");

	return ret;
}

