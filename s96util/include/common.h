#ifndef __COMMON_H
#define __COMMON_H

#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))

#define ZONE_CONFIG_LEN_MAX	128

#define SLOT_CONFIG_NUM_WORDS	8
#define SLOT_CONFIG_OFFSET	20
#define SLOT_CONFIG_START_WORD	5

#define KEY_CONFIG_NUM_WORDS	8
#define KEY_CONFIG_OFFSET	96
#define KEY_CONFIG_START_WORD	24

#define DATA_NUM_SLOTS		16 /* Total number of slots in data zone */
#define OTP_NUM_WORDS		2  /* Total number of slots in otp zone */

#endif
