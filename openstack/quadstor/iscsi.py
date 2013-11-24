#	Copyright (C) QUADStor Systems
#	Copyright (C) Shivaram Upadhyayula <shivaram.u@quadstor.com>
#
"""
QUADStor Cinder ISCSI Driver
"""

from cinder import exception
from cinder.openstack.common import log as logging
from cinder.volume import volume_types
from cinder.volume.drivers.san.san import SanISCSIDriver
from cinder.volume.drivers.quadstor.common import *

LOG = logging.getLogger(__name__)
class QUADStorSanISCSIDriver(SanISCSIDriver):

	def __init__(self, *args, **kwargs):
		super(QUADStorSanISCSIDriver, self).__init__(*args, **kwargs)
        	self.configuration.append_config_values(quadstor_opts)

	def _update_volume_status(self):
		backend_name = self.configuration.safe_get('volume_backend_name')
		data = {}
		data['driver_version'] = '0.1'
		data['total_capacity_gb'] = 'infinite'
		data['free_capacity_gb'] = 'infinite'
		data['reserved_percentage'] = 0
		data['storage_protocol'] = 'iSCSI'
		data['vendor_name'] = 'QUADStor'
		data['volume_backend_name'] = backend_name or self.__class__.__name__
        	self._stats = data 

	def _build_iscsi_target_name(self, volume):
		return quadstor_iscsi_target_name(self, volume)

	def create_volume(self, volume):
		quadstor_create_volume(self, volume)
		vupdate = {}
		portal = "%s:3260,1" % self.configuration.safe_get("san_ip"); 
		iqn = quadstor_iscsi_target_name(self, volume)
		vupdate['provider_location'] = ("%s %s 0" % (portal, iqn))
		return vupdate

	def delete_volume(self, volume):
		quadstor_delete_volume(self, volume['name'])

	def extend_volume(self, volume, new_size):
		quadstor_extend_volume(self, volume, new_size)

	def local_path(self, volume):
		msg = _("local_path is not supported by this driver")
		raise exception.VolumeBackendAPIException(data=msg)

	def get_volume_stats(self, refresh=False):
		if refresh:
			self._update_volume_status()

		return self._stats

	def create_snapshot(self, snapshot):
		quadstor_create_clone(self, snapshot['volume_name'], snapshot['name'])

	def create_volume_from_snapshot(self, volume, snapshot):
		quadstor_create_clone(self, snapshot['name'], volume['name'])

	def delete_snapshot(self, snapshot):
		quadstor_delete_volume(self, snapshot['name'])
