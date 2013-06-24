/* 
 * Copyright (C) Shivaram Upadhyayula <shivaram.u@quadstor.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * Version 2 as published by the Free Software Foundation
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, 
 * Boston, MA  02110-1301, USA.
 */

#include <bsddefs.h>
#include <ioctldefs.h>
#include <exportdefs.h>

sx_t ioctl_lock;

static struct qs_kern_cbs kcbs;

MALLOC_DEFINE(M_COREBSD, "corebsd", "QUADStor allocations");
static int
coremod_ioctl(struct cdev *dev, unsigned long cmd, caddr_t arg, int fflag, struct thread *td)
{
	void __user *userp = (void __user *)arg;
	int retval = 0;
	struct bdev_info *bdev_info;
	struct tdisk_info *tdisk_info;
	struct mdaemon_info mdaemon_info;
	struct node_config *node_config;
	struct clone_config clone_config;
	struct group_conf *group_conf;
	struct fc_rule_config fc_rule_config;

	sx_xlock(&ioctl_lock);
	switch(cmd) {
	case TLTARGIOCDAEMONSETINFO:
		memcpy(&mdaemon_info, arg, sizeof(mdaemon_info));
		(*kcbs.mdaemon_set_info)(&mdaemon_info);
		break;
	case TLTARGIOCNODECONFIG:
	case TLTARGIOCNODESTATUS:
		node_config = malloc(sizeof(*node_config), M_COREBSD, M_NOWAIT);
		if (!node_config) {
			retval = -ENOMEM;
			break;
		}

		if (cmd == TLTARGIOCNODECONFIG) {
			memcpy(node_config, arg, sizeof(*node_config));
			retval = (*kcbs.node_config)(node_config);
		}
		else if (cmd == TLTARGIOCNODESTATUS) {
			retval = (*kcbs.node_status)(node_config);
			memcpy(userp, node_config, sizeof(*node_config));
		}
		free(node_config, M_COREBSD);
		break;
	case TLTARGIOCREMOVEFCRULE:
		memcpy(&fc_rule_config, arg, sizeof(fc_rule_config));
		if (cmd == TLTARGIOCADDFCRULE)
			retval = (*kcbs.target_add_fc_rule)(&fc_rule_config);
		else if (cmd == TLTARGIOCREMOVEFCRULE)
			retval = (*kcbs.target_remove_fc_rule)(&fc_rule_config);
		else
			retval = -1;
		break;
	case TLTARGIOCCLONEVDISK:
	case TLTARGIOCCLONESTATUS:
	case TLTARGIOCCLONECANCEL:
	case TLTARGIOCMIRRORVDISK:
	case TLTARGIOCMIRRORSTATUS:
	case TLTARGIOCMIRRORCANCEL:
	case TLTARGIOCMIRRORREMOVE:
		memcpy(&clone_config, arg, sizeof(clone_config));
		if (cmd == TLTARGIOCCLONEVDISK) {
			retval = (*kcbs.vdisk_clone)(&clone_config);
		}
		else if (cmd == TLTARGIOCCLONESTATUS) {
			retval = (*kcbs.vdisk_clone_status)(&clone_config);
			if (retval == 0)
				memcpy(userp, &clone_config, sizeof(clone_config));
		}
		else if (cmd == TLTARGIOCCLONECANCEL) {
			retval = (*kcbs.vdisk_clone_cancel)(&clone_config);
		}
		else if (cmd == TLTARGIOCMIRRORVDISK) {
			retval = (*kcbs.vdisk_mirror)(&clone_config);
			memcpy(userp, &clone_config, sizeof(clone_config));
		}
		else if (cmd == TLTARGIOCMIRRORSTATUS) {
			retval = (*kcbs.vdisk_mirror_status)(&clone_config);
			if (retval == 0)
				memcpy(userp, &clone_config, sizeof(clone_config));
		}
		else if (cmd == TLTARGIOCMIRRORCANCEL) {
			retval = (*kcbs.vdisk_mirror_cancel)(&clone_config);
		}
		else if (cmd == TLTARGIOCMIRRORREMOVE) {
			retval = (*kcbs.vdisk_mirror_remove)(&clone_config);
		}
		else {
			retval = -1;
		}
		break;
	case TLTARGIOCNEWBLKDEV:
	case TLTARGIOCDELBLKDEV:
	case TLTARGIOCNEWBDEVSTUB:
	case TLTARGIOCDELETEBDEVSTUB:
	case TLTARGIOCGETBLKDEV:
	case TLTARGIOCHACONFIG:
	case TLTARGIOCUNMAPCONFIG:
	case TLTARGIOCWCCONFIG:
		bdev_info = malloc(sizeof(struct bdev_info), M_COREBSD, M_WAITOK);
		if (!bdev_info) {
			retval = -ENOMEM;
			break;
		}

		memcpy(bdev_info, arg, sizeof(struct bdev_info));
		if (cmd == TLTARGIOCNEWBLKDEV)
			retval = (*kcbs.bdev_add_new)(bdev_info);
		else if (cmd == TLTARGIOCDELBLKDEV)
			retval = (*kcbs.bdev_remove)(bdev_info);
		else if (cmd == TLTARGIOCNEWBDEVSTUB)
			retval = (*kcbs.bdev_add_stub)(bdev_info);
		else if (cmd == TLTARGIOCDELETEBDEVSTUB)
			retval = (*kcbs.bdev_remove_stub)(bdev_info);
		else if (cmd == TLTARGIOCGETBLKDEV)
			retval = (*kcbs.bdev_get_info)(bdev_info);
		else if (cmd == TLTARGIOCHACONFIG)
			retval = (*kcbs.bdev_ha_config)(bdev_info);
		else if (cmd == TLTARGIOCUNMAPCONFIG)
			retval = (*kcbs.bdev_unmap_config)(bdev_info);
		else if (cmd == TLTARGIOCWCCONFIG)
			retval = (*kcbs.bdev_wc_config)(bdev_info);
		memcpy(userp, bdev_info, sizeof(struct bdev_info));
		free(bdev_info, M_COREBSD);
		break;
	case TLTARGIOCLOADDONE:
		retval = (*kcbs.coremod_load_done)();
		break;
	case TLTARGIOCRESETLOGS:
		retval = (*kcbs.coremod_reset_logs)();
		break;
	case TLTARGIOCUNLOAD:
		retval = (*kcbs.coremod_exit)();
		break;
	case TLTARGIOCADDGROUP:
	case TLTARGIOCDELETEGROUP:
	case TLTARGIOCRENAMEGROUP:
		group_conf = malloc(sizeof(*group_conf), M_COREBSD, M_WAITOK);
		if (!group_conf) {
			retval = -ENOMEM;
			break;
		}
		memcpy(group_conf, arg, sizeof(*group_conf));
		if (cmd == TLTARGIOCADDGROUP)
			retval = (*kcbs.bdev_add_group)(group_conf);
		else if (cmd == TLTARGIOCDELETEGROUP)
			retval = (*kcbs.bdev_delete_group)(group_conf);
		else if (cmd == TLTARGIOCRENAMEGROUP)
			retval = (*kcbs.bdev_rename_group)(group_conf);
		free(group_conf, M_COREBSD);
		break;
	case TLTARGIOCDELETETDISK:
	case TLTARGIOCDELETETDISKPOST:
	case TLTARGIOCNEWTDISK:
	case TLTARGIOCATTACHTDISK:
	case TLTARGIOCLOADTDISK:
	case TLTARGIOCMODIFYTDISK:
	case TLTARGIOCTDISKSTATS:
	case TLTARGIOCTDISKRESETSTATS:
	case TLTARGIOCNEWTDISKSTUB:
	case TLTARGIOCDELETETDISKSTUB:
	case TLTARGIOCDISABLETDISKSTUB:
	case TLTARGIOCRESIZETDISK:
	case TLTARGIOCRENAMETDISK:
	case TLTARGIOCSETMIRRORROLE:
		tdisk_info = malloc(sizeof(struct tdisk_info), M_COREBSD, M_WAITOK);
		if (!tdisk_info) {
			retval = -ENOMEM;
			break;
		}

		memcpy(tdisk_info, arg, offsetof(struct tdisk_info, q_entry));
		if (cmd == TLTARGIOCLOADTDISK)
			retval = (*kcbs.target_load_vdisk)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCATTACHTDISK)
			retval = (*kcbs.target_attach_vdisk)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCMODIFYTDISK)
			retval = (*kcbs.target_modify_vdisk)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCDELETETDISK)
			retval = (*kcbs.target_delete_vdisk)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCDELETETDISKPOST)
			retval = (*kcbs.target_delete_vdisk_post)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCTDISKSTATS)
			retval = (*kcbs.target_vdisk_stats)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCTDISKRESETSTATS)
			retval = (*kcbs.target_vdisk_reset_stats)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCNEWTDISK)
			retval = (*kcbs.target_new_vdisk)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCNEWTDISKSTUB)
			retval = (*kcbs.target_new_vdisk_stub)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCDELETETDISKSTUB)
			retval = (*kcbs.target_delete_vdisk_stub)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCDISABLETDISKSTUB)
			retval = (*kcbs.target_disable_vdisk_stub)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCRESIZETDISK)
			retval = (*kcbs.target_resize_vdisk)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCRENAMETDISK)
			retval = (*kcbs.target_rename_vdisk)(tdisk_info, (unsigned long)arg);
		else if (cmd == TLTARGIOCSETMIRRORROLE)
			retval = (*kcbs.target_set_role)(tdisk_info, (unsigned long)arg);
		free(tdisk_info, M_COREBSD);
		break;
	default:
		break;
	}
	sx_xunlock(&ioctl_lock);

	if (retval == -1)
		retval = (EIO);
	else if (retval < 0)
		retval = -(retval);
	return retval;
}

struct cdev *tldev;
static struct cdevsw tldev_csw = {
	.d_version = D_VERSION,
	.d_ioctl = coremod_ioctl,
};

static int coremod_init(void)
{
	int retval;

	sx_init(&ioctl_lock, "core ioctl lck");

	retval = kern_interface_init(&kcbs);
	if (retval != 0) {
		return -1;
	}

	tldev = make_dev(&tldev_csw, 0, UID_ROOT, GID_WHEEL, 0550, "iodev");
	return 0; 
}

static void
coremod_exit(void)
{
	sx_xlock(&ioctl_lock);
	kern_interface_exit();
	sx_xunlock(&ioctl_lock);

	destroy_dev(tldev);
}

static struct module *coremod;

int
device_register_interface(struct qs_interface_cbs *icbs)
{
	int retval;

	MOD_XLOCK;
	module_reference(coremod);
	MOD_XUNLOCK;
	retval = __device_register_interface(icbs);
	if (retval != 0) {
		MOD_XLOCK;
		module_release(coremod);
		MOD_XUNLOCK;
	}
	return retval;
}

void
device_unregister_interface(struct qs_interface_cbs *icbs)
{
	int retval;

	retval = __device_unregister_interface(icbs);
	if (retval == 0) {
		MOD_XLOCK;
		module_release(coremod);
		MOD_XUNLOCK;
	}
}

static int
event_handler(struct module *module, int event, void *arg) {
	int retval = 0;
	switch (event) {
	case MOD_LOAD:
		retval = coremod_init();
		if (retval == 0)
			coremod = module;		
		break;
	case MOD_UNLOAD:
		coremod_exit();
		break;
	default:
		retval = EOPNOTSUPP;
		break;
	}
        return retval;
}

static moduledata_t tldev_info = {
    "tldev",    /* module name */
     event_handler,  /* event handler */
     NULL            /* extra data */
};

DECLARE_MODULE(tldev, tldev_info, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(tldev, 1);
