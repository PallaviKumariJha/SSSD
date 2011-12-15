/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SSS_SUDO_H_
#define SSS_SUDO_H_

#include <stdint.h>

#ifndef EOK
#define EOK 0
#endif

#define SSS_SUDO_ERROR_OK   0

struct sss_attr {
    char *name;
    char **values;
    unsigned int num_values;
};

struct sss_rule {
    unsigned int num_attrs;
    struct sss_attr *attrs;
};

struct sss_result {
    unsigned int num_rules;
    struct sss_rule *rules;
};

int sss_sudo_get_result(const char *username,
                        uint32_t *_error,
                        struct sss_result **_result);

void sss_sudo_free_result(struct sss_result *result);

int sss_sudo_get_values(struct sss_rule *e,
                        const char *attrname,
                        char ***values);

void sss_sudo_free_values(char **values);

#endif /* SSS_SUDO_H_ */