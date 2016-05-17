api_version:
  description: ""
  default: null
build:
  description: ""
  default: null
ccdb_ng.address:
  description: ""
  default: null
ccdb_ng.databases:
  description: ""
  default: null
ccdb_ng.max_connections:
  description: ""
  default: null
ccdb_ng.pool_timeout:
  description: ""
  default: null
ccdb_ng.port:
  description: ""
  default: null
ccdb_ng.roles:
  description: ""
  default: null
ccng.bootstrap_admin_email:
  description: ""
  default: null
ccng.bulk_api_password:
  description: ""
  default: null
ccng.bulk_api_user:
  description: ""
  default: null
ccng.cc_partition:
  description: ""
  default: null
ccng.db_logging_level:
  description: ""
  default: null
ccng.default_quota_definition:
  description: ""
  default: free
ccng.external_host:
  description: ""
  default: null
ccng.logging_level:
  description: ""
  default: info
ccng.logging_max_retries:
  description: ""
  default: 1
ccng.max_staging_runtime:
  description: ""
  default: null
ccng.quota_definitions.free.free_memory_limit:
  description: ""
  default: 1024
ccng.quota_definitions.free.non_basic_services_allowed:
  description: ""
  default: false
ccng.quota_definitions.free.paid_memory_limit:
  description: ""
  default: 0
ccng.quota_definitions.free.total_services:
  description: ""
  default: 2
ccng.quota_definitions.paid.free_memory_limit:
  description: ""
  default: 1024
ccng.quota_definitions.paid.non_basic_services_allowed:
  description: ""
  default: true
ccng.quota_definitions.paid.paid_memory_limit:
  description: ""
  default: 32768
ccng.quota_definitions.paid.total_services:
  description: ""
  default: 32
ccng.quota_definitions.runaway.free_memory_limit:
  description: ""
  default: 1024
ccng.quota_definitions.runaway.non_basic_services_allowed:
  description: ""
  default: true
ccng.quota_definitions.runaway.paid_memory_limit:
  description: ""
  default: 204800
ccng.quota_definitions.runaway.total_services:
  description: ""
  default: 500
ccng.quota_definitions.yeti.free_memory_limit:
  description: ""
  default: 204800
ccng.quota_definitions.yeti.non_basic_services_allowed:
  description: ""
  default: true
ccng.quota_definitions.yeti.paid_memory_limit:
  description: ""
  default: 204800
ccng.quota_definitions.yeti.total_services:
  description: ""
  default: 500
ccng.staging_upload_password:
  description: ""
  default: null
ccng.staging_upload_user:
  description: ""
  default: null
ccng.system_domains:
  description: ""
  default: null
ccng.uaa_resource_id:
  description: ""
  default: null
ccng.use_nginx:
  description: ""
  default: null
description:
  description: ""
  default: null
directories.droplets:
  description: ""
  default: /var/vcap/shared/droplets
directories.resources:
  description: ""
  default: /var/vcap/shared/resources
directories.staging_manifests:
  description: ""
  default: /var/vcap/jobs/cloud_controller_ng/config/staging
directories.tmpdir:
  description: ""
  default: /var/vcap/data/cloud_controller_ng/tmp
domain:
  description: ""
  default: null
name:
  description: ""
  default: null
nats.address:
  description: ""
  default: null
nats.password:
  description: ""
  default: null
nats.port:
  description: ""
  default: null
nats.user:
  description: ""
  default: null
networks.apps:
  description: ""
  default: null
nfs_server:
  description: NFS share for droplets and apps
  default: null
serialization_data_server.port:
  description: ""
  default: null
serialization_data_server.upload_timeout:
  description: ""
  default: null
serialization_data_server.upload_token:
  description: ""
  default: null
service_lifecycle.serialization_data_server:
  description: ""
  default: null
support_address:
  description: ""
  default: null
syslog_aggregator:
  description: ""
  default: null
uaa.cc.token_secret:
  description: ""
  default: null
vcap_redis.address:
  description: ""
  default: null
vcap_redis.password:
  description: ""
  default: null
vcap_redis.port:
  description: ""
  default: null
version:
  description: ""
  default: null

