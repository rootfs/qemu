/*
 * Copyright 2016, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
*/

#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <scsi/scsi.h>

#include "tcmu-runner.h"

#include "qemu/osdep.h"
#include <getopt.h>
#include <libgen.h>

#include "qapi/error.h"
#include "qemu-io.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "qemu/readline.h"
#include "qapi/qmp/qstring.h"
#include "qom/object_interfaces.h"
#include "sysemu/block-backend.h"
#include "block/block_int.h"
#include "trace/control.h"
#include "crypto/init.h"
#include "migration/vmstate.h"

void handler_init(void);
int qemu_handler_open(struct tcmu_device *dev);
void qemu_handler_close(struct tcmu_device *dev);
int qemu_handle_cmd(
	struct tcmu_device *dev,
	struct tcmulib_cmd *tcmulib_cmd);

const VMStateDescription vmstate_dummy;

const VMStateInfo vmstate_info_bool;

const VMStateInfo vmstate_info_int8;
const VMStateInfo vmstate_info_int16;
const VMStateInfo vmstate_info_int32;
const VMStateInfo vmstate_info_int64;

const VMStateInfo vmstate_info_uint8_equal;
const VMStateInfo vmstate_info_uint16_equal;
const VMStateInfo vmstate_info_int32_equal;
const VMStateInfo vmstate_info_uint32_equal;
const VMStateInfo vmstate_info_uint64_equal;
const VMStateInfo vmstate_info_int32_le;

const VMStateInfo vmstate_info_uint8;
const VMStateInfo vmstate_info_uint16;
const VMStateInfo vmstate_info_uint32;
const VMStateInfo vmstate_info_uint64;

const VMStateInfo vmstate_info_float64;
const VMStateInfo vmstate_info_cpudouble;

const VMStateInfo vmstate_info_timer;
const VMStateInfo vmstate_info_buffer;
const VMStateInfo vmstate_info_unused_buffer;
const VMStateInfo vmstate_info_bitmap;

struct qemu_handler_state {
	BlockBackend *drv;
	uint64_t num_lbas;
	uint32_t block_size;
};
    
static bool qemu_check_config(const char *cfgstring, char **reason)
{
	return true;
}

static BlockBackend *openfile(char *name)
{
    Error *local_err = NULL;
    BlockDriverState *bs;

    BlockBackend *qemuio_blk = blk_new_open(name, NULL, NULL, BDRV_O_RDWR, &local_err);
    if (!qemuio_blk) {
        error_reportf_err(local_err, "can't open%s%s: ",
                          name ? " device " : "", name ?: "");
        return NULL;
    }

    bs = blk_bs(qemuio_blk);
    if (bdrv_is_encrypted(bs) && bdrv_key_required(bs)) {
        char password[256];
        printf("Disk image '%s' is encrypted.\n", name);
        if (qemu_read_password(password, sizeof(password)) < 0) {
            error_report("No password given");
            goto error;
        }
        if (bdrv_set_key(bs, password) < 0) {
            error_report("invalid password");
            goto error;
        }
    }

    blk_set_enable_write_cache(qemuio_blk, false);

    return qemuio_blk;

 error:
    blk_unref(qemuio_blk);
    return NULL;
}

int qemu_handler_open(struct tcmu_device *dev)
{
    struct qemu_handler_state *state;
	int64_t size;
	char *config;
	state = calloc(1, sizeof(*state));
	if (!state)
		return -ENOMEM;

	tcmu_set_dev_private(dev, state);

	state->block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (state->block_size == -1) {
		errp("Could not get device block size\n");
		return -EINVAL;
	}

	size = tcmu_get_device_size(dev);
	if (size == -1) {
		errp("Could not get device size\n");
		return -EINVAL;
	}

	state->num_lbas = size / state->block_size;

	config = tcmu_get_dev_cfgstring(dev);
	if (!config) {
		errp("no configuration found in cfgstring\n");
		return -EINVAL;
	}

	state->drv = openfile(config);
    
	if (!state->drv) {
		errp("could not open %s: %m\n", config);
        return -EIO;
	}
    return 0;
}

void qemu_handler_close(struct tcmu_device *dev)
{
    struct qemu_handler_state *state = tcmu_get_dev_private(dev);
	blk_unref(state->drv);
	free(state);
}

int qemu_handle_cmd(
	struct tcmu_device *dev,
	struct tcmulib_cmd *tcmulib_cmd)
{
    uint8_t *cdb = tcmulib_cmd->cdb;
	struct iovec *iovec = tcmulib_cmd->iovec;
	size_t iov_cnt = tcmulib_cmd->iov_cnt;
	uint8_t *sense = tcmulib_cmd->sense_buf;
	struct qemu_handler_state *state = tcmu_get_dev_private(dev);
	uint8_t cmd;

	cmd = cdb[0];

	switch (cmd) {
	case INQUIRY:
		return tcmu_emulate_inquiry(dev, cdb, iovec, iov_cnt, sense);
		break;
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);
		break;
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return tcmu_emulate_read_capacity_16(state->num_lbas,
							     state->block_size,
							     cdb, iovec, iov_cnt, sense);
		else
			return TCMU_NOT_HANDLED;
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(cdb, iovec, iov_cnt, sense);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(cdb, iovec, iov_cnt, sense);
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	{
#if 0
        int remaining;
        size_t ret;
		void *buf;
		uint64_t offset;
		int length = tcmu_get_xfer_length(cdb) * state->block_size;

		/* Using this buf DTRT even if seek is beyond EOF */
		buf = malloc(length);
		if (!buf)
			return set_medium_error(sense);
		memset(buf, 0, length);
        offset = state->block_size * tcmu_get_lba(cdb);

		ret = pread(state->fd, buf, length, offset);
		if (ret == -1) {
			errp("read failed: %m\n");
			free(buf);
			return set_medium_error(sense);
		}

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, length);

		free(buf);
#endif
		return SAM_STAT_GOOD;
	}
	break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	{
/*    
		uint64_t offset = state->block_size * tcmu_get_lba(cdb);
		int length = be16toh(*((uint16_t *)&cdb[7])) * state->block_size;

		remaining = length;

		while (remaining) {
			unsigned int to_copy;

			to_copy = (remaining > iovec->iov_len) ? iovec->iov_len : remaining;
			ret = pwrite(state->fd, iovec->iov_base, to_copy, offset);
			if (ret == -1) {
				errp("Could not write: %m\n");
				return set_medium_error(sense);
			}

			remaining -= to_copy;
			offset += to_copy;
			iovec++;
		}
*/
		return SAM_STAT_GOOD;
	}
	break;
	default:
		errp("unknown command %x\n", cdb[0]);
		return TCMU_NOT_HANDLED;
	}
    return 0;
}
char qemu_cfg_desc[] =
	"The path to the qemu block URL to use as a backstore.";

static struct tcmur_handler qemu_handler = {
	.cfg_desc = qemu_cfg_desc,
	.check_config = qemu_check_config,
	.open = qemu_handler_open,
	.close = qemu_handler_close,
	.name = "qemu",
	.subtype = "qemu",
	.handle_cmd = qemu_handle_cmd,
};

void handler_init(void)
{
	tcmur_register_handler(&qemu_handler);
}
