#	Copyright (C) QUADStor Systems
#	Copyright (C) Shivaram Upadhyayula <shivaram.u@quadstor.com>
#
"""
QUADStor Cinder Common
"""

from oslo.config import cfg
from cinder.openstack.common import log as logging
from cinder.volume.drivers.san.san import SanISCSIDriver

LOG = logging.getLogger(__name__)

quadstor_opts = [
	cfg.StrOpt('vdisk_compression',
		   default='off',
		   help='Enable/Disable VDisk compression'),
	cfg.StrOpt('vdisk_pool',
		   default=None,
		   help='Storage pool for VDisks'),
	cfg.StrOpt('vdisk_deduplication',
		   default='on',
		   help='Enable/Disable VDisk deduplication'),
	cfg.StrOpt('vdisk_volume_prefix',
		   default='',
		   help='Prefix for VDisk names to identify that it is a cinder volume/snapshot'),
	]

def quadstor_iscsi_target_name(self, volume):
	volume_prefix = self.configuration.safe_get('vdisk_volume_prefix')
	iqn = "%s%s%s" % (self.configuration.iscsi_target_prefix, volume_prefix, volume['name'])
	return iqn

def quadstor_create_volume(self, volume):
	args = ["/quadstor/bin/vdconfig"]
	volume_prefix = self.configuration.safe_get('vdisk_volume_prefix')
	args.append(" -a -v '%s%s'" % (volume_prefix, volume['name']))
	if int(volume['size']) == 0:
		args.append(" -s 100")
	else:
		args.append(" -s %s" % volume['size'])
	pool = self.configuration.safe_get('vdisk_pool')
	if pool:
		args.append(" -g '%s'" % pool)
	args.append(" -e")
	compression = self.configuration.safe_get('vdisk_compression')
	if compression and compression == 'on':
		args.append(" -c")
	dedupe = self.configuration.safe_get('vdisk_deduplication')
	if dedupe == None or dedupe != 'off':
		args.append(" -d")
	iqn = "%s%s%s" % (self.configuration.iscsi_target_prefix, volume_prefix, volume['name'])
	args.append(" -i '%s'" % iqn)
	cmd = ''.join(args)
       	LOG.debug(_("Create volume cmd %s"), cmd)
	self._run_ssh(cmd)

def quadstor_delete_volume(self, name): 
	args = ["/quadstor/bin/vdconfig"]
	volume_prefix = self.configuration.safe_get('vdisk_volume_prefix')
	args.append(" -x -v '%s%s' -f" % (volume_prefix, name))
	cmd = ''.join(args)
       	LOG.debug(_("Delete volume cmd %s"), cmd)
	self._run_ssh(cmd)

def quadstor_extend_volume(self, volume, new_size):
	args = ["/quadstor/bin/vdconfig"]
	volume_prefix = self.configuration.safe_get('vdisk_volume_prefix')
	args.append(" -v '%s%s' -f" % (volume_prefix, volume['name']))
	if int(new_size) == 0:
		args.append(" -s 100")
	else:
		args.append(" -s %s" % new_size)
	cmd = ''.join(args)
       	LOG.debug(_("Extend volume cmd %s"), cmd)
	self._run_ssh(cmd)

def quadstor_create_clone(self, src, dest):
	args = ["/quadstor/bin/qclone"]
	volume_prefix = self.configuration.safe_get('vdisk_volume_prefix')
	args.append(" -s '%s%s' -d '%s%s' -w" % (volume_prefix, src, volume_prefix, dest))
	cmd = ''.join(args)
       	LOG.debug(_("Clone volume cmd %s"), cmd)
	self._run_ssh(cmd)
