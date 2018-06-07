#ifndef __ATECC508A_H
#define __ATECC508A_H

#include <secure96/s96at.h>

int atecc508a_read_config(struct s96at_desc *desc, uint8_t *buf);

int atecc508a_personalize_config(struct s96at_desc *desc);

int atecc508a_personalize_data(struct s96at_desc *desc);

#endif
