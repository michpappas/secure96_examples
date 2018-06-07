#ifndef __ATSHA204A_H
#define __ATSHA204A_H

#include <secure96/s96at.h>

int atsha204a_read_config(struct s96at_desc *desc, uint8_t *buf);

int atsha204a_personalize_config(struct s96at_desc *desc);

int atsha204a_personalize_data(struct s96at_desc *desc);

#endif
