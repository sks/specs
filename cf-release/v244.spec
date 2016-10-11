acceptance_tests.addresses:
  description: A list of addresses which will be checked for TCP connectivity and
    features
  default:
  - 10.244.14.2
acceptance_tests.admin_password:
  description: The Elastic Runtime API admin user's password
  default: null
acceptance_tests.admin_user:
  description: The Elastic Runtime API admin user
  default: null
acceptance_tests.api:
  description: The Elastic Runtime API endpoint URL
  default: null
acceptance_tests.apps_domain:
  description: The Elastic Runtime Application Domain
  default: null
acceptance_tests.async_service_operation_timeout:
  description: Timeout for asynchronous service operations
  default: null
acceptance_tests.backend:
  description: App tests push their apps using the backend specified. Route service
    tests require this flag to be set to diego in order to run.
  default: ""
acceptance_tests.binary_buildpack_name:
  description: The name of the binary buildpack to use in acceptance tests that specify
    a buildpack.
  default: null
acceptance_tests.broker_start_timeout:
  description: Timeout for broker starts
  default: null
acceptance_tests.cf_dial_timeout_in_seconds:
  description: Sets the cli timeout (CF_DIAL_TIMEOUT)
  default: null
acceptance_tests.cf_push_timeout:
  description: Timeout for cf push
  default: null
acceptance_tests.cloud_controller.admin_password:
  description: Cloud Controller admin user's password
  default: null
acceptance_tests.cloud_controller.admin_user:
  description: Cloud Controller admin user
  default: null
acceptance_tests.cloud_controller.api:
  description: URL of the Cloud Controller API
  default: null
acceptance_tests.cloud_controller.apps_domain:
  description: App domain that will be created
  default: null
acceptance_tests.cloud_controller.use_http:
  description: Flag for using HTTP when making application requests rather than the
    default HTTPS
  default: false
acceptance_tests.default_timeout:
  description: Default Timeout
  default: null
acceptance_tests.enable_color:
  description: Enable colorized output on ginkgo.
  default: true
acceptance_tests.existing_user:
  description: The username of an existing user. If set, the acceptance-tests will
    push apps and perform other actions as this user, otherwise its default behaviour
    is to create a temporary user for such actions.
  default: null
acceptance_tests.existing_user_password:
  description: The password of the existing user. Only required if the existing user
    property is also being set.
  default: null
acceptance_tests.go_buildpack_name:
  description: The name of the go buildpack to use in acceptance tests that specify
    a buildpack.
  default: null
acceptance_tests.include_apps:
  description: Flag to include the apps test suite.
  default: true
acceptance_tests.include_backend_compatibility:
  description: Flag to inlude whether we check DEA/Diego interoperability
  default: false
acceptance_tests.include_detect:
  description: Flag to run tests in the detect suite
  default: true
acceptance_tests.include_diego_docker:
  description: Flag to include tests related to running Docker apps on Diego. Diego
    must be deployed and the CC API docker_diego feature flag must be enabled for
    these tests to pass.
  default: false
acceptance_tests.include_diego_ssh:
  description: Flag to include the diego ssh suite
  default: false
acceptance_tests.include_internet_dependent:
  description: Flag to include the internet dependent test suite.
  default: false
acceptance_tests.include_privileged_container_support:
  description: Flag for running tests that depend on privileged container support
    being enabled in your Cloud Foundry.
  default: null
acceptance_tests.include_route_services:
  description: Flag to include the route services tests. Diego must be deployed for
    these tests to pass.
  default: false
acceptance_tests.include_routing:
  description: Flag to include the routing tests. Diego must be deployed for these
    tests to pass.
  default: true
acceptance_tests.include_security_groups:
  description: Flag to include the security groups test suite.
  default: false
acceptance_tests.include_services:
  description: Flag to include the services API test suite.
  default: false
acceptance_tests.include_sso:
  description: Flag to include the services tests that integrate with SSO.
  default: false
acceptance_tests.include_tasks:
  description: Flag to include the v3 task tests dependent on the CC task_creation
    feature flag.
  default: false
acceptance_tests.include_v3:
  description: Flag to include the v3 API test suite.
  default: false
acceptance_tests.java_buildpack_name:
  description: The name of the java buildpack to use in acceptance tests that specify
    a buildpack.
  default: null
acceptance_tests.long_curl_timeout:
  description: Timeout for long curls
  default: null
acceptance_tests.nodejs_buildpack_name:
  description: The name of the nodejs buildpack to use in acceptance tests that specify
    a buildpack.
  default: null
acceptance_tests.nodes:
  description: The number of parallel test executors to spawn. The larger the number
    the higher the stress on the system.
  default: 4
acceptance_tests.persistent_app_host:
  description: The default name for the persistent app host.
  default: null
acceptance_tests.persistent_app_org:
  description: The default name for the persistent app org.
  default: null
acceptance_tests.persistent_app_quota_name:
  description: The default name for the persistent app quota name.
  default: null
acceptance_tests.persistent_app_space:
  description: The default name for the persistent app space.
  default: null
acceptance_tests.php_buildpack_name:
  description: The name of the php buildpack to use in acceptance tests that specify
    a buildpack.
  default: null
acceptance_tests.python_buildpack_name:
  description: The name of the python buildpack to use in acceptance tests that specify
    a buildpack.
  default: null
acceptance_tests.ruby_buildpack_name:
  description: The name of the ruby buildpack to use in acceptance tests that specify
    a buildpack.
  default: null
acceptance_tests.skip_regex:
  description: Regex for tests that should be skipped
  default: null
acceptance_tests.skip_ssl_validation:
  description: When true, does not verify TLS certificates for any API calls made
    during the test run
  default: false
acceptance_tests.staticfile_buildpack_name:
  description: The name of the staticfile buildpack to use in acceptance tests that
    specify a buildpack.
  default: null
acceptance_tests.system_domain:
  description: ""
  default: null
acceptance_tests.use_http:
  description: Flag for using HTTP when making api and application requests rather
    than the default HTTPS
  default: false
acceptance_tests.verbose:
  description: Whether to pass the -v flag to router acceptance tests
  default: false
app_domains:
  description: 'Array of domains for user apps (example: ''user.app.space.foo'', a
    user app called ''neat'' will listen at ''http://neat.user.app.space.foo'')'
  default: null
app_ssh.host_key_fingerprint:
  description: MD5 fingerprint of the host key of the SSH proxy that brokers connections
    to application instances
  default: null
app_ssh.oauth_client_id:
  description: The oauth client ID of the SSH proxy
  default: ssh-proxy
app_ssh.port:
  description: External port for SSH access to application instances
  default: 2222
bbs.api_location:
  description: Diego BBS Server endpoint URL.
  default: http://bbs.service.cf.internal:8889
bbs.ca_cert:
  description: PEM-encoded CA certificate used to sign TLS certificate hosted by Diego
    BBS.
  default: null
bbs.require_ssl:
  description: Enables mutual-TLS communication with Diego BBS.
  default: true
blobstore.admin_users:
  description: |
    List of Username and Password pairs that have admin access to the blobstore. Cloud Controller must use one of these to access the blobstore via HTTP Basic Auth.
    Example:
      users:
      - username: user1
        password: password1
      - username: user2
        password: password2
  default: null
blobstore.internal_access_rules:
  description: List of allow / deny rules for the blobstore internal server. Defaults
    to RFC 1918 Private Networks. Will be followed by 'deny all'. See http://nginx.org/en/docs/http/ngx_http_access_module.html
    for valid rules
  default:
  - allow 10.0.0.0/8;
  - allow 172.16.0.0/12;
  - allow 192.168.0.0/16;
blobstore.max_upload_size:
  description: Max allowed file size for upload
  default: 5000m
blobstore.nginx_workers_per_core:
  description: Number of NGINX worker processes per CPU core
  default: 2
blobstore.port:
  description: TCP port on which the blobstore server (nginx) listens
  default: 8080
blobstore.secure_link.secret:
  description: The secret used for signing URLs
  default: null
blobstore.tls.cert:
  description: The PEM-encoded certificate (optionally as a certificate chain) for
    serving blobs over TLS/SSL
  default: null
blobstore.tls.port:
  description: The TCP port on which the internal blobstore server listens
  default: 4443
blobstore.tls.private_key:
  description: The PEM-encoded private key for signing TLS/SSL traffic
  default: null
boshhmforwarder.debug_port:
  description: the http port for the debug endpoint - set to '-1' to disable debugging
  default: -1
boshhmforwarder.incoming_port:
  description: the port for the boshhmforwarder
  default: 4000
boshhmforwarder.info_port:
  description: the http port for the info endpoint
  default: 4003
boshhmforwarder.logLevel:
  description: the logLevel for the boshhmforwarder
  default: INFO
build:
  description: '''build'' attribute in the /v2/info endpoint'
  default: ""
capi.cc_uploader.cc.external_port:
  description: External Cloud Controller port
  default: 9022
capi.cc_uploader.cc.job_polling_interval_in_seconds:
  description: the interval between job polling requests
  default: null
capi.cc_uploader.consul_agent_port:
  description: local consul agent's port
  default: 8500
capi.cc_uploader.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17018
capi.cc_uploader.dropsonde_port:
  description: local metron agent's port
  default: 3457
capi.cc_uploader.listen_addr:
  description: Address of interface on which to serve files
  default: 0.0.0.0:9090
capi.cc_uploader.log_level:
  description: Log level
  default: info
capi.nsync.bbs.api_location:
  description: Address to the BBS Server
  default: bbs.service.cf.internal:8889
capi.nsync.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
capi.nsync.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
capi.nsync.bbs.client_key:
  description: PEM-encoded client key
  default: null
capi.nsync.bbs.client_session_cache_size:
  description: capacity of the tls client cache
  default: null
capi.nsync.bbs.max_idle_conns_per_host:
  description: maximum number of idle http connections
  default: null
capi.nsync.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
capi.nsync.bulker_debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17007
capi.nsync.cc.base_url:
  description: base URL of the cloud controller
  default: null
capi.nsync.cc.basic_auth_password:
  description: basic auth password for CC bulk API
  default: null
capi.nsync.cc.basic_auth_username:
  description: basic auth username for CC bulk API
  default: internal_user
capi.nsync.cc.bulk_batch_size:
  description: number of apps to fetch at once from bulk API
  default: 500
capi.nsync.cc.external_port:
  description: External Cloud Controller port
  default: 9022
capi.nsync.cc.fetch_timeout_in_seconds:
  description: How long to wait for completion of requests to CC in seconds.
  default: 30
capi.nsync.cc.polling_interval_in_seconds:
  description: interval at which to poll bulk API in seconds
  default: 30
capi.nsync.consul_agent_port:
  description: local consul agent's port
  default: 8500
capi.nsync.diego_privileged_containers:
  description: Whether or not to use privileged containers for  buildpack based LRPs
    and tasks. Containers with a docker-image-based rootfs will continue to always
    be unprivileged and cannot be changed.
  default: false
capi.nsync.dropsonde_port:
  description: local metron agent's port
  default: 3457
capi.nsync.file_server_url:
  description: URL of file server
  default: http://file-server.service.cf.internal:8080
capi.nsync.lifecycle_bundles:
  description: List of lifecycle bundles arguments for different stacks in form 'lifecycle-name:path/to/bundle'
  default:
  - buildpack/cflinuxfs2:buildpack_app_lifecycle/buildpack_app_lifecycle.tgz
  - buildpack/windows2012R2:windows_app_lifecycle/windows_app_lifecycle.tgz
  - docker:docker_app_lifecycle/docker_app_lifecycle.tgz
capi.nsync.listen_addr:
  description: Address from which nsync serves requests
  default: 0.0.0.0:8787
capi.nsync.listener_debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17006
capi.nsync.log_level:
  description: Log level
  default: info
capi.stager.bbs.api_location:
  description: Address to the BBS Server
  default: bbs.service.cf.internal:8889
capi.stager.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
capi.stager.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
capi.stager.bbs.client_key:
  description: PEM-encoded client key
  default: null
capi.stager.bbs.client_session_cache_size:
  description: capacity of the tls client cache
  default: null
capi.stager.bbs.max_idle_conns_per_host:
  description: maximum number of idle http connections
  default: null
capi.stager.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
capi.stager.cc.basic_auth_password:
  description: Basic auth password for CC internal API
  default: null
capi.stager.cc.basic_auth_username:
  description: Basic auth username for CC internal API
  default: internal_user
capi.stager.cc.external_port:
  description: External port to access the Cloud Controller
  default: 9022
capi.stager.cc.internal_service_hostname:
  description: Internal CC host name
  default: cloud-controller-ng.service.cf.internal
capi.stager.cc_uploader_url:
  description: URL of cc uploader
  default: http://cc-uploader.service.cf.internal:9090
capi.stager.consul_agent_port:
  description: local consul agent's port
  default: 8500
capi.stager.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17011
capi.stager.diego_privileged_containers:
  description: Whether or not to use privileged containers for staging tasks.
  default: false
capi.stager.docker_registry_address:
  description: Address of the Docker Registry used for image caching
  default: docker-registry.service.cf.internal:8080
capi.stager.docker_staging_stack:
  description: stack to use for staging Docker applications
  default: cflinuxfs2
capi.stager.dropsonde_port:
  description: local metron agent's port
  default: 3457
capi.stager.file_server_url:
  description: URL of file server
  default: http://file-server.service.cf.internal:8080
capi.stager.insecure_docker_registry_list:
  description: An array of insecure Docker registries in the form of <HOSTNAME|IP>:PORT
  default: []
capi.stager.lifecycle_bundles:
  description: List of lifecycle bundles arguments for different stacks in form 'lifecycle-name:path/to/bundle'
  default:
  - buildpack/cflinuxfs2:buildpack_app_lifecycle/buildpack_app_lifecycle.tgz
  - buildpack/windows2012R2:windows_app_lifecycle/windows_app_lifecycle.tgz
  - docker:docker_app_lifecycle/docker_app_lifecycle.tgz
capi.stager.listen_addr:
  description: Address from which the Stager serves requests
  default: 0.0.0.0:8888
capi.stager.log_level:
  description: Log level
  default: info
capi.stager.staging_task_callback_url:
  description: URL for staging task callbacks
  default: http://stager.service.cf.internal:8888
capi.tps.bbs.api_location:
  description: Address to the BBS Server
  default: bbs.service.cf.internal:8889
capi.tps.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
capi.tps.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
capi.tps.bbs.client_key:
  description: PEM-encoded client key
  default: null
capi.tps.bbs.client_session_cache_size:
  description: capacity of the tls client cache
  default: null
capi.tps.bbs.max_idle_conns_per_host:
  description: maximum number of idle http connections
  default: null
capi.tps.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
capi.tps.cc.basic_auth_password:
  description: Basic auth password for CC internal API
  default: null
capi.tps.cc.basic_auth_username:
  description: Basic auth username for CC internal API
  default: internal_user
capi.tps.cc.external_port:
  description: External port to access the Cloud Controller
  default: 9022
capi.tps.cc.internal_service_hostname:
  description: Internal CC host name
  default: cloud-controller-ng.service.cf.internal
capi.tps.consul_agent_port:
  description: local consul agent's port
  default: 8500
capi.tps.dropsonde_port:
  description: local metron agent's port
  default: 3457
capi.tps.listener.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17014
capi.tps.listener.listen_addr:
  description: address at which to serve API requests
  default: 0.0.0.0:1518
capi.tps.log_level:
  description: Log level
  default: info
capi.tps.max_in_flight_requests:
  description: Maximum number of requests to handle at once.
  default: 200
capi.tps.traffic_controller_url:
  description: URL of Traffic controller
  default: null
capi.tps.watcher.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17015
cc.allow_app_ssh_access:
  description: Allow users to change the value of the app-level allow_ssh attribute
  default: true
cc.allowed_cors_domains:
  description: List of domains (including scheme) from which Cross-Origin requests
    will be accepted, a * can be used as a wildcard for any part of a domain
  default: []
cc.app_bits_max_body_size:
  description: Maximum body size for nginx bits uploads
  default: 1536M
cc.app_bits_upload_grace_period_in_seconds:
  description: Extra token expiry time while uploading big apps.
  default: 1200
cc.app_events.cutoff_age_in_days:
  description: How old an app event should stay in cloud controller database before
    being cleaned up
  default: 31
cc.app_usage_events.cutoff_age_in_days:
  description: How old an app usage event should stay in cloud controller database
    before being cleaned up
  default: 31
cc.audit_events.cutoff_age_in_days:
  description: How old an audit event should stay in cloud controller database before
    being cleaned up
  default: 31
cc.bits_service.enabled:
  description: Enable integration of the bits-service incubator (experimental)
  default: false
cc.bits_service.private_endpoint:
  description: Private url for the bits-service service
  default: ""
cc.bits_service.public_endpoint:
  description: Public url for the bits-service service
  default: ""
cc.broker_client_default_async_poll_interval_seconds:
  description: Specifies interval on which the CC will poll a service broker for asynchronous
    actions
  default: 60
cc.broker_client_max_async_poll_duration_minutes:
  description: The max duration the CC will fetch service instance state from a service
    broker. Default is 1 week
  default: 10080
cc.broker_client_timeout_seconds:
  description: For requests to service brokers, this is the HTTP (open and read) timeout
    setting.
  default: 60
cc.buildpacks.blobstore_type:
  description: 'The type of blobstore backing to use. Valid values: [''fog'', ''webdav'']'
  default: fog
cc.buildpacks.buildpack_directory_key:
  description: Directory (bucket) used store buildpacks.  It does not have be pre-created.
  default: cc-buildpacks
cc.buildpacks.cdn.key_pair_id:
  description: Key pair name for signed download URIs
  default: ""
cc.buildpacks.cdn.private_key:
  description: Private key for signing download URIs
  default: ""
cc.buildpacks.cdn.uri:
  description: URI for a CDN to used for buildpack downloads
  default: ""
cc.buildpacks.fog_aws_storage_options:
  description: 'Storage options passed to fog for aws blobstores. Valid keys: [''encryption''].'
  default: null
cc.buildpacks.fog_connection:
  description: Fog connection hash
  default: null
cc.buildpacks.webdav_config.blobstore_timeout:
  description: The timeout in seconds for requests to the blobstore
  default: 5
cc.buildpacks.webdav_config.ca_cert:
  description: The ca cert to use when communicating with webdav
  default: ""
cc.buildpacks.webdav_config.password:
  description: The basic auth password that CC uses to connect to the admin endpoint
    on webdav
  default: ""
cc.buildpacks.webdav_config.private_endpoint:
  description: 'The location of the webdav server eg: https://blobstore.internal'
  default: https://blobstore.service.cf.internal:4443
cc.buildpacks.webdav_config.public_endpoint:
  description: 'The location of the webdav server eg: https://blobstore.com'
  default: ""
cc.buildpacks.webdav_config.username:
  description: The basic auth user that CC uses to connect to the admin endpoint on
    webdav
  default: ""
cc.bulk_api_password:
  description: Password for the bulk api
  default: null
cc.bulk_api_user:
  description: User used to access the bulk_api, health_manager uses it to connect
    to the cc, announced over NATS
  default: bulk_api
cc.cc_partition:
  description: Deprecated. Defines a 'partition' for the health_manager job
  default: default
cc.client_max_body_size:
  description: Maximum body size for nginx
  default: 1536M
cc.completed_tasks.cutoff_age_in_days:
  description: How long a completed task will stay in cloud controller database before
    being cleaned up based on last updated time with success or failure.
  default: 31
cc.core_file_pattern:
  description: Filename template for core dump files. Use an empty string if you don't
    want core files saved.
  default: /var/vcap/sys/cores/core-%e-%s-%p-%t
cc.db_encryption_key:
  description: key for encrypting sensitive values in the CC database
  default: ""
cc.db_logging_level:
  description: Log level for cc database operations
  default: debug2
cc.dea_use_https:
  description: enable ssl for communication with DEAs
  default: false
cc.default_app_disk_in_mb:
  description: The default disk space an app gets
  default: 1024
cc.default_app_memory:
  description: How much memory given to an app if not specified
  default: 1024
cc.default_health_check_timeout:
  description: Default health check timeout (in seconds) that can be set for the app
  default: 60
cc.default_quota_definition:
  description: Local to use a local (NFS) file system.  AWS to use AWS.
  default: default
cc.default_running_security_groups:
  description: The default running security groups that will be seeded in CloudController.
  default: null
cc.default_stack:
  description: The default stack to use if no custom stack is specified by an app.
  default: cflinuxfs2
cc.default_staging_security_groups:
  description: The default staging security groups that will be seeded in CloudController.
  default: null
cc.default_to_diego_backend:
  description: Use Diego backend by default for new apps
  default: false
cc.development_mode:
  description: Enable development features for monitoring and insight
  default: false
cc.diego.nsync_url:
  description: URL of the Diego nsync service
  default: http://nsync.service.cf.internal:8787
cc.diego.stager_url:
  description: URL of the Diego stager service
  default: http://stager.service.cf.internal:8888
cc.diego.tps_url:
  description: URL of the Diego tps service
  default: http://tps.service.cf.internal:1518
cc.directories.diagnostics:
  description: The directory where operator requested diagnostic files should be placed
  default: /var/vcap/data/cloud_controller_ng/diagnostics
cc.directories.tmpdir:
  description: The directory to use for temporary files
  default: /var/vcap/data/cloud_controller_ng/tmp
cc.disable_custom_buildpacks:
  description: Disable external (i.e. git) buildpacks? (Admin buildpacks and system
    buildpacks only.)
  default: false
cc.droplets.blobstore_type:
  description: 'The type of blobstore backing to use. Valid values: [''fog'', ''webdav'']'
  default: fog
cc.droplets.cdn.key_pair_id:
  description: Key pair name for signed download URIs
  default: ""
cc.droplets.cdn.private_key:
  description: Private key for signing download URIs
  default: ""
cc.droplets.cdn.uri:
  description: URI for a CDN to used for droplet downloads
  default: ""
cc.droplets.droplet_directory_key:
  description: Directory (bucket) used store droplets.  It does not have be pre-created.
  default: cc-droplets
cc.droplets.fog_aws_storage_options:
  description: 'Storage options passed to fog for aws blobstores. Valid keys: [''encryption''].'
  default: null
cc.droplets.fog_connection:
  description: Fog connection hash
  default: null
cc.droplets.max_staged_droplets_stored:
  description: Number of recent, staged droplets stored per app (not including current
    droplet)
  default: 5
cc.droplets.webdav_config.blobstore_timeout:
  description: The timeout in seconds for requests to the blobstore
  default: 5
cc.droplets.webdav_config.ca_cert:
  description: The ca cert to use when communicating with webdav
  default: ""
cc.droplets.webdav_config.password:
  description: The basic auth password that CC uses to connect to the admin endpoint
    on webdav
  default: ""
cc.droplets.webdav_config.private_endpoint:
  description: 'The location of the webdav server eg: https://blobstore.internal'
  default: https://blobstore.service.cf.internal:4443
cc.droplets.webdav_config.public_endpoint:
  description: 'The location of the webdav server eg: https://blobstore.com'
  default: ""
cc.droplets.webdav_config.username:
  description: The basic auth user that CC uses to connect to the admin endpoint on
    webdav
  default: ""
cc.external_host:
  description: Host part of the cloud_controller api URI, will be joined with value
    of 'domain'
  default: api
cc.external_port:
  description: External port to connect to the CC
  default: 9022
cc.external_protocol:
  description: The protocol used to access the CC API from an external entity
  default: https
cc.failed_jobs.cutoff_age_in_days:
  description: How old a failed job should stay in cloud controller database before
    being cleaned up
  default: 31
cc.feature_disabled_message:
  description: Custom message to use for a disabled feature.
  default: null
cc.flapping_crash_count_threshold:
  description: The threshold of crashes after which the app is marked as flapping
  default: 3
cc.info.custom:
  description: Custom attribute keys and values for /v2/info endpoint
  default: null
cc.install_buildpacks:
  description: Set of buildpacks to install during deploy
  default: null
cc.instance_file_descriptor_limit:
  description: The file descriptors made available to each app instance
  default: 16384
cc.internal_api_password:
  description: Password for hm9000 API
  default: null
cc.internal_api_user:
  description: Username for hm9000 API
  default: internal_user
cc.internal_service_hostname:
  description: Internal hostname used to resolve the address of the Cloud Controller
  default: cloud-controller-ng.service.cf.internal
cc.jobs.app_bits_packer.timeout_in_seconds:
  description: The longest this job can take before it is cancelled
  default: null
cc.jobs.app_events_cleanup.timeout_in_seconds:
  description: The longest this job can take before it is cancelled
  default: null
cc.jobs.app_usage_events_cleanup.timeout_in_seconds:
  description: The longest this job can take before it is cancelled
  default: null
cc.jobs.blobstore_delete.timeout_in_seconds:
  description: The longest this job can take before it is cancelled
  default: null
cc.jobs.blobstore_upload.timeout_in_seconds:
  description: The longest this job can take before it is cancelled
  default: null
cc.jobs.droplet_deletion.timeout_in_seconds:
  description: The longest this job can take before it is cancelled
  default: null
cc.jobs.droplet_upload.timeout_in_seconds:
  description: The longest this job can take before it is cancelled
  default: null
cc.jobs.generic.number_of_workers:
  description: Number of generic cloud_controller_worker workers
  default: 1
cc.jobs.global.timeout_in_seconds:
  description: The longest any job can take before it is cancelled unless overriden
    per job
  default: 14400
cc.jobs.local.number_of_workers:
  description: Number of local cloud_controller_worker workers
  default: 2
cc.logging_level:
  description: Log level for cc
  default: info
cc.logging_max_retries:
  description: Passthru value for Steno logger
  default: 1
cc.maximum_app_disk_in_mb:
  description: The maximum amount of disk a user can request
  default: 2048
cc.maximum_health_check_timeout:
  description: Maximum health check timeout (in seconds) that can be set for the app
  default: 180
cc.min_cli_version:
  description: Minimum version of the CF CLI to work with the API.
  default: null
cc.min_recommended_cli_version:
  description: Minimum recommended version of the CF CLI.
  default: null
cc.minimum_candidate_stagers:
  description: Minimum number of candidate deas for staging.  Defaults to 5, should
    be fewer than the total DEAs in the deployment.
  default: 5
cc.newrelic.capture_params:
  description: Capture and send query params to NewRelic
  default: false
cc.newrelic.developer_mode:
  description: Activate NewRelic developer mode
  default: false
cc.newrelic.environment_name:
  description: The environment name used by NewRelic
  default: development
cc.newrelic.license_key:
  description: The api key for NewRelic
  default: null
cc.newrelic.log_file_path:
  description: The location for NewRelic to log to
  default: /var/vcap/sys/log/cloud_controller_ng/newrelic
cc.newrelic.monitor_mode:
  description: Activate NewRelic monitor mode
  default: false
cc.newrelic.transaction_tracer.enabled:
  description: Enable transaction tracing in NewRelic
  default: false
cc.newrelic.transaction_tracer.record_sql:
  description: 'NewRelic''s SQL statement recording mode: [off | obfuscated | raw]'
  default: "off"
cc.nginx_access_log_destination:
  description: The nginx access log destination. This can be used to route access
    logs to a file, syslog, or a memory buffer.
  default: /var/vcap/sys/log/nginx_cc/nginx.access.log
cc.nginx_access_log_format:
  description: The nginx log format string to use when writing to the access log.
  default: |
    $host - [$time_local] "$request" $status $bytes_sent "$http_referer" "$http_user_agent" $proxy_add_x_forwarded_for vcap_request_id:$upstream_http_x_vcap_request_id response_time:$upstream_response_time
cc.nginx_error_log_destination:
  description: The nginx error log destination. This can be used to route error logs
    to a file, syslog, or a memory buffer.
  default: /var/vcap/sys/log/nginx_cc/nginx.error.log
cc.nginx_error_log_level:
  description: The lowest severity nginx log level to capture in the error log.
  default: error
cc.nginx_rate_limit_general:
  description: The rate limiting and burst value to use for '/'
  default: null
cc.nginx_rate_limit_zones:
  description: 'Array of zones to do rate limiting for. '
  default: null
cc.packages.app_package_directory_key:
  description: Directory (bucket) used store app packages.  It does not have be pre-created.
  default: cc-packages
cc.packages.blobstore_type:
  description: 'The type of blobstore backing to use. Valid values: [''fog'', ''webdav'']'
  default: fog
cc.packages.cdn.key_pair_id:
  description: Key pair name for signed download URIs
  default: ""
cc.packages.cdn.private_key:
  description: Private key for signing download URIs
  default: ""
cc.packages.cdn.uri:
  description: URI for a CDN to used for app package downloads
  default: ""
cc.packages.fog_aws_storage_options:
  description: 'Storage options passed to fog for aws blobstores. Valid keys: [''encryption''].'
  default: null
cc.packages.fog_connection:
  description: Fog connection hash
  default: null
cc.packages.max_package_size:
  description: Maximum size of application package
  default: 1073741824
cc.packages.max_valid_packages_stored:
  description: Number of recent, valid packages stored per app (not including package
    for current droplet)
  default: 5
cc.packages.webdav_config.blobstore_timeout:
  description: The timeout in seconds for requests to the blobstore
  default: 5
cc.packages.webdav_config.ca_cert:
  description: The ca cert to use when communicating with webdav
  default: ""
cc.packages.webdav_config.password:
  description: The basic auth password that CC uses to connect to the admin endpoint
    on webdav
  default: ""
cc.packages.webdav_config.private_endpoint:
  description: 'The location of the webdav server eg: https://blobstore.internal'
  default: https://blobstore.service.cf.internal:4443
cc.packages.webdav_config.public_endpoint:
  description: 'The location of the webdav server eg: https://blobstore.com'
  default: ""
cc.packages.webdav_config.username:
  description: The basic auth user that CC uses to connect to the admin endpoint on
    webdav
  default: ""
cc.pending_packages.expiration_in_seconds:
  description: How long packages can remain in pending state before being cleaned
    up
  default: 1200
cc.pending_packages.frequency_in_seconds:
  description: How often the package pending cleanup job runs
  default: 300
cc.placement_top_stager_percentage:
  description: The percentage of top stagers considered when choosing a stager
  default: 10
cc.quota_definitions:
  description: Hash of default quota definitions. Overriden by custom quota definitions.
  default: null
cc.renderer.default_results_per_page:
  description: Default number of results returned per page if user does not specify
  default: 50
cc.renderer.max_inline_relations_depth:
  description: Maximum depth of inlined relationships in the result
  default: 2
cc.renderer.max_results_per_page:
  description: Maximum number of results returned per page
  default: 100
cc.reserved_private_domains:
  description: File location of a list of reserved private domains (for file format,
    see https://publicsuffix.org/)
  default: null
cc.resource_pool.blobstore_type:
  description: 'The type of blobstore backing to use. Valid values: [''fog'', ''webdav'']'
  default: fog
cc.resource_pool.cdn.key_pair_id:
  description: Key pair name for signed download URIs
  default: ""
cc.resource_pool.cdn.private_key:
  description: Private key for signing download URIs
  default: ""
cc.resource_pool.cdn.uri:
  description: URI for a CDN to used for resource pool downloads
  default: ""
cc.resource_pool.fog_aws_storage_options:
  description: 'Storage options passed to fog for aws blobstores. Valid keys: [''encryption''].'
  default: null
cc.resource_pool.fog_connection:
  description: Fog connection hash
  default: null
cc.resource_pool.maximum_size:
  description: Maximum size of a resource to add to the pool
  default: 536870912
cc.resource_pool.minimum_size:
  description: Minimum size of a resource to add to the pool
  default: 65536
cc.resource_pool.resource_directory_key:
  description: Directory (bucket) used store app resources.  It does not have be pre-created.
  default: cc-resources
cc.resource_pool.webdav_config.blobstore_timeout:
  description: The timeout in seconds for requests to the blobstore
  default: 5
cc.resource_pool.webdav_config.ca_cert:
  description: The ca cert to use when communicating with webdav
  default: ""
cc.resource_pool.webdav_config.password:
  description: The basic auth password that CC uses to connect to the admin endpoint
    on webdav
  default: ""
cc.resource_pool.webdav_config.private_endpoint:
  description: 'The location of the webdav server eg: https://blobstore.internal'
  default: https://blobstore.service.cf.internal:4443
cc.resource_pool.webdav_config.public_endpoint:
  description: 'The location of the webdav server eg: https://blobstore.com'
  default: ""
cc.resource_pool.webdav_config.username:
  description: The basic auth user that CC uses to connect to the admin endpoint on
    webdav
  default: ""
cc.run_prestart_migrations:
  description: Run Cloud Controller DB migrations in BOSH pre-start script. Should
    be changed to false for deployments where the PostgreSQL job is deployed to the
    same VM as Cloud Controller. Otherwise, the default of true is preferable.
  default: true
cc.security_event_logging.enabled:
  description: Enable logging of all requests made to the Cloud Controller in CEF
    format.
  default: false
cc.security_group_definitions:
  description: Array of security groups that will be seeded into CloudController.
  default: null
cc.service_usage_events.cutoff_age_in_days:
  description: How old a service usage event should stay in cloud controller database
    before being cleaned up
  default: 31
cc.srv_api_uri:
  description: API URI of cloud controller
  default: null
cc.stacks:
  description: Tag used by the DEA to describe capabilities (i.e. 'Windows7', 'python-linux').
    DEA and CC must agree.
  default:
  - description: Cloud Foundry Linux-based filesystem
    name: cflinuxfs2
cc.staging_file_descriptor_limit:
  description: File descriptor limit for staging tasks
  default: 16384
cc.staging_timeout_in_seconds:
  description: Timeout for staging a droplet
  default: 900
cc.staging_upload_password:
  description: User's password used to access internal endpoints of Cloud Controller
    to upload files when staging
  default: ""
cc.staging_upload_user:
  description: User name used to access internal endpoints of Cloud Controller to
    upload files when staging
  default: ""
cc.statsd_host:
  description: The host for the statsd server, defaults to the local metron agent
  default: 127.0.0.1
cc.statsd_port:
  description: The port for the statsd server, defaults to the local metron agent
  default: 8125
cc.system_hostnames:
  description: List of hostnames for which routes cannot be created on the system
    domain.
  default:
  - api
  - uaa
  - login
  - doppler
  - loggregator
  - hm9000
cc.thresholds.api.alert_if_above_mb:
  description: The cc will alert if memory remains above this threshold for 3 monit
    cycles
  default: 3500
cc.thresholds.api.restart_if_above_mb:
  description: The cc will restart if memory remains above this threshold for 3 monit
    cycles
  default: 3750
cc.thresholds.api.restart_if_consistently_above_mb:
  description: The cc will restart if memory remains above this threshold for 15 monit
    cycles
  default: 3500
cc.thresholds.worker.alert_if_above_mb:
  description: The cc will alert if memory remains above this threshold for 3 monit
    cycles
  default: 384
cc.thresholds.worker.restart_if_above_mb:
  description: The cc will restart if memory remains above this threshold for 3 monit
    cycles
  default: 512
cc.thresholds.worker.restart_if_consistently_above_mb:
  description: The cc will restart if memory remains above this threshold for 15 monit
    cycles
  default: 384
cc.uaa_resource_id:
  description: Name of service to register to UAA
  default: cloud_controller,cloud_controller_service_permissions
cc.users_can_select_backend:
  description: Allow non-admin users to switch their apps between DEA and Diego backends
  default: true
cc.volume_services_enabled:
  description: Enable binding to services that provide volume_mount information.
  default: false
ccdb.address:
  description: The address of the database server
  default: null
ccdb.databases:
  description: Contains the name of the database on the database server
  default: null
ccdb.db_scheme:
  description: The type of database being used. mysql or postgres
  default: postgres
ccdb.max_connections:
  description: Maximum connections for Sequel
  default: 25
ccdb.pool_timeout:
  description: The timeout for Sequel pooled connections
  default: 10
ccdb.port:
  description: The port of the database server
  default: null
ccdb.roles:
  description: Users to create on the database when seeding
  default: null
collector.aws.access_key_id:
  description: AWS access key for CloudWatch access
  default: null
collector.aws.secret_access_key:
  description: AWS secret for CloudWatch access
  default: null
collector.datadog.api_key:
  description: Datadog API key
  default: null
collector.datadog.application_key:
  description: Datadog application key
  default: null
collector.deployment_name:
  description: name for this bosh deployment. All metrics will be tagged with deployment:XXX
    when sending them to CloudWatch, Datadog and Graphite
  default: null
collector.graphite.address:
  description: IP address of Graphite
  default: null
collector.graphite.port:
  description: TCP port of Graphite
  default: null
collector.intervals.discover:
  description: the interval in seconds that the collector attempts to discover components
  default: 60
collector.intervals.healthz:
  description: the interval in seconds that healthz is checked
  default: 30
collector.intervals.local_metrics:
  description: the interval in seconds that local_metrics are checked
  default: 30
collector.intervals.nats_ping:
  description: the interval in seconds that the collector pings nats to record latency
  default: 30
collector.intervals.prune:
  description: the interval in seconds that the collector attempts to prune unresponsive
    components
  default: 300
collector.intervals.varz:
  description: the interval in seconds that varz is checked
  default: 30
collector.logging_level:
  description: the logging level for the collector
  default: info
collector.memory_threshold:
  description: Memory threshold for collector restart (Mb)
  default: 800
collector.opentsdb.address:
  description: IP address of OpenTsdb
  default: null
collector.opentsdb.port:
  description: TCP port of OpenTsdb
  default: null
collector.use_aws_cloudwatch:
  description: enable CloudWatch plugin
  default: false
collector.use_datadog:
  description: enable Datadog plugin
  default: false
collector.use_graphite:
  description: enable Graphite plugin
  default: false
collector.use_tsdb:
  description: enable OpenTsdb plugin
  default: false
consul.acceptance_tests.aws.access_key_id:
  description: Key ID for AWS deployments
  default: ""
consul.acceptance_tests.aws.cloud_config_subnets:
  description: Subnet ID for AWS deployments utilizing the Cloud Config
  default: ""
consul.acceptance_tests.aws.default_key_name:
  description: Default Key Name for AWS deployments
  default: bosh
consul.acceptance_tests.aws.default_security_groups:
  description: Security groups for AWS deployments
  default: []
consul.acceptance_tests.aws.region:
  description: Region for AWS deployments
  default: us-east-1
consul.acceptance_tests.aws.secret_access_key:
  description: Secret Access Key for AWS deployments
  default: ""
consul.acceptance_tests.aws.subnets:
  description: Subnet ID for AWS deployments
  default: ""
consul.acceptance_tests.bosh.director_ca_cert:
  description: BOSH Director CA Cert
  default: ""
consul.acceptance_tests.bosh.password:
  description: BOSH Director password
  default: admin
consul.acceptance_tests.bosh.target:
  description: Location of the BOSH Director to target when deploying consul
  default: 192.168.50.4
consul.acceptance_tests.bosh.username:
  description: BOSH Director username
  default: admin
consul.acceptance_tests.consul_release_version:
  description: The default consul-release version number to deploy
  default: latest
consul.acceptance_tests.parallel_nodes:
  description: Number of parallel nodes to use for tests
  default: 1
consul.acceptance_tests.registry.host:
  description: Host for the BOSH registry
  default: 127.0.0.1
consul.acceptance_tests.registry.password:
  description: Password for the BOSH registry
  default: password
consul.acceptance_tests.registry.port:
  description: Port for the BOSH registry
  default: 25777
consul.acceptance_tests.registry.username:
  description: Username for the BOSH registry
  default: admin
consul.agent.datacenter:
  description: Name of the agent's datacenter.
  default: dc1
consul.agent.dns_config.allow_stale:
  description: Enables a stale query for DNS information. This allows any Consul server,
    rather than only the leader, to service the request.
  default: false
consul.agent.dns_config.max_stale:
  description: When allow_stale is specified, this is used to limit how stale results
    are allowed to be.
  default: 5s
consul.agent.dns_config.recursor_timeout:
  description: Timeout used by Consul when recursively querying an upstream DNS server.
  default: 5s
consul.agent.domain:
  description: Domain suffix for DNS
  default: null
consul.agent.log_level:
  description: Agent log level.
  default: info
consul.agent.mode:
  description: Mode to run the agent in. (client or server)
  default: client
consul.agent.protocol_version:
  description: The Consul protocol to use.
  default: 2
consul.agent.servers.lan:
  description: LAN server addresses to join on start.
  default: []
consul.agent.servers.wan:
  description: WAN server addresses to join.
  default: []
consul.agent.services:
  description: Map of consul service definitions.
  default: {}
consul.agent_cert:
  description: PEM-encoded agent certificate
  default: null
consul.agent_key:
  description: PEM-encoded client key
  default: null
consul.ca_cert:
  description: PEM-encoded CA certificate
  default: null
consul.encrypt_keys:
  description: A list of passphrases that will be converted into encryption keys,
    the first key in the list is the active one
  default: null
consul.server_cert:
  description: PEM-encoded server certificate
  default: null
consul.server_key:
  description: PEM-encoded server key
  default: null
consul.servers:
  description: comma-separated list of consul server URLs (scheme://ip:port)
  default: http://127.0.0.1:8500
databases.additional_config:
  description: A map of additional key/value pairs to include as extra configuration
    properties
  default: null
databases.address:
  description: The database address
  default: null
databases.collect_statement_statistics:
  description: Enable the `pg_stat_statements` extension and collect statement execution
    statistics
  default: false
databases.databases:
  description: A list of databases and associated properties to create
  default: null
databases.db_scheme:
  description: The database scheme
  default: null
databases.log_line_prefix:
  description: The postgres `printf` style string that is output at the beginning
    of each log line
  default: '%m: '
databases.max_connections:
  description: Maximum number of database connections
  default: null
databases.port:
  description: The database port
  default: null
databases.roles:
  description: A list of database roles and associated properties to create
  default: null
dea_logging_agent.debug:
  description: boolean value to turn on verbose mode
  default: false
dea_next.advertise_interval_in_seconds:
  description: frequency of staging & DEA advertisments in seconds.
  default: 5
dea_next.allow_host_access:
  description: Allows warden containers to access the DEA host via its IP
  default: false
dea_next.allow_networks:
  description: ""
  default: null
dea_next.ca_cert:
  description: PEM-encoded CA certificate
  default: null
dea_next.client_cert:
  description: PEM-encoded server certificate
  default: null
dea_next.client_key:
  description: PEM-encoded server key
  default: null
dea_next.crash_lifetime_secs:
  description: Crashed app lifetime in seconds
  default: 3600
dea_next.default_health_check_timeout:
  description: Default timeout for application to start
  default: 60
dea_next.directory_server_protocol:
  description: The protocol to use when communicating with the directory server ("http"
    or "https")
  default: https
dea_next.disk_mb:
  description: ""
  default: 32000
dea_next.disk_overcommit_factor:
  description: ""
  default: 1
dea_next.dns_servers:
  description: List of nameservers to use in containers
  default: null
dea_next.enable_ssl:
  description: enable ssl for all communication with DEAs
  default: true
dea_next.evacuation_bail_out_time_in_seconds:
  description: Duration to wait before shutting down, in seconds.
  default: 115
dea_next.heartbeat_interval_in_seconds:
  description: Heartbeat interval for DEAs
  default: null
dea_next.instance_bandwidth_limit.burst:
  description: Network bandwidth burst limit for running instances in bytes
  default: null
dea_next.instance_bandwidth_limit.rate:
  description: Network bandwidth limit for running instances in bytes per second
  default: null
dea_next.instance_disk_inode_limit:
  description: Limit on inodes for an instance container
  default: 200000
dea_next.instance_max_cpu_share_limit:
  description: The maximum number of CPU shares that can be given to an app
  default: 256
dea_next.instance_memory_to_cpu_share_ratio:
  description: Controls the relationship between app memory and cpu shares. app_cpu_shares
    = app_memory / cpu_share_factor
  default: 8
dea_next.instance_min_cpu_share_limit:
  description: The minimum number of CPU shares that can be given to an app
  default: 1
dea_next.instance_nproc_limit:
  description: Limit on nproc for an instance container
  default: 512
dea_next.kernel_network_tuning_enabled:
  description: with latest kernel version, no kernel network tunings allowed with
    in warden cpi containers
  default: true
dea_next.logging_level:
  description: Log level for DEA.
  default: debug
dea_next.max_staging_duration:
  description: ""
  default: 900
dea_next.memory_mb:
  description: ""
  default: 8000
dea_next.memory_overcommit_factor:
  description: ""
  default: 1
dea_next.mtu:
  description: Interface MTU size
  default: 1500
dea_next.post_setup_hook:
  description: 'DEPRECATED: a single line of bash to prepend to the start command'
  default: null
dea_next.rlimit_core:
  description: Maximum size of core file in bytes. 0 represents no core dump files
    can be created, and -1 represents no size limits.
  default: 0
dea_next.server_cert:
  description: PEM-encoded server certificate
  default: null
dea_next.server_key:
  description: PEM-encoded server key
  default: null
dea_next.ssl_port:
  description: SSL port for DEA
  default: 22443
dea_next.stacks:
  description: An array of stacks, specifying the name and package path.
  default:
  - name: cflinuxfs2
    package_path: /var/vcap/packages/rootfs_cflinuxfs2/rootfs
dea_next.staging_bandwidth_limit.burst:
  description: Network bandwidth burst limit for staging tasks in bytes
  default: null
dea_next.staging_bandwidth_limit.rate:
  description: Network bandwidth limit for staging tasks in bytes per second
  default: null
dea_next.staging_cpu_limit_shares:
  description: CPU limit in shares for staging tasks cgroup
  default: 512
dea_next.staging_disk_inode_limit:
  description: Limit on inodes for a staging container
  default: 200000
dea_next.staging_disk_limit_mb:
  description: Disk limit in mb for staging tasks
  default: 6144
dea_next.staging_memory_limit_mb:
  description: Memory limit in mb for staging tasks
  default: 1024
dea_next.streaming_timeout:
  description: ""
  default: 60
dea_next.zone:
  description: The Availability Zone
  default: default
description:
  description: '''description'' attribute in the /v2/info endpoint'
  default: ""
diego.ssl.skip_cert_verify:
  description: when connecting over https, ignore bad ssl certificates
  default: false
disk_quota_enabled:
  description: disk quota must be disabled to use warden-inside-warden with the warden
    cpi
  default: true
dns_health_check_host:
  description: Host to ping for confirmation of DNS resolution
  default: consul.service.cf.internal
domain:
  description: Deprecated in favor of system_domain. Domain where cloud_controller
    will listen (api.domain)
  default: null
doppler.blacklisted_syslog_ranges:
  description: Blacklist for IPs that should not be used as syslog drains, e.g. internal
    ip addresses.
  default: null
doppler.container_metric_ttl_seconds:
  description: TTL (in seconds) for container usage metrics
  default: 120
doppler.debug:
  description: boolean value to turn on verbose logging for doppler system (dea agent
    & doppler server)
  default: false
doppler.dropsonde_incoming_port:
  description: Port for incoming udp messages
  default: 3457
doppler.enabled:
  description: Whether to expose the doppler_logging_endpoint listed at /v2/info
  default: true
doppler.etcd.client_cert:
  description: PEM-encoded client certificate
  default: ""
doppler.etcd.client_key:
  description: PEM-encoded client key
  default: ""
doppler.grpc_port:
  description: Port for outgoing log messages via GRPC
  default: 8082
doppler.incoming_tcp_port:
  description: Port for incoming tcp messages
  default: 3458
doppler.locked_memory_limit:
  description: Size (KB) of shell's locked memory limit. Set to 'kernel' to use the
    kernel's default. Non-numeric values other than 'kernel', 'soft', 'hard', and
    'unlimited' will result in an error.
  default: unlimited
doppler.maxRetainedLogMessages:
  description: number of log messages to retain per application
  default: 100
doppler.message_drain_buffer_size:
  description: Size of the internal buffer used by doppler to store messages for output
    to firehose or 'cf logs'. If the buffer gets full doppler will drop the messages.
  default: 10000
doppler.outgoing_port:
  description: Port for outgoing doppler messages
  default: 8081
doppler.port:
  description: Port for doppler_logging_endpoint listed at /v2/info
  default: 443
doppler.sink_dial_timeout_seconds:
  description: Dial timeout for sinks
  default: 1
doppler.sink_inactivity_timeout_seconds:
  description: Interval before removing a sink due to inactivity
  default: 3600
doppler.sink_io_timeout_seconds:
  description: I/O Timeout on sinks
  default: 0
doppler.syslog_skip_cert_verify:
  description: When connecting over TLS, don't verify certificates for syslog sink
  default: true
doppler.tls.enable:
  description: Enable TLS listener on doppler so that it can receive dropsonde envelopes
    over TLS transport. If enabled, Cert and Key files must be specified.
  default: false
doppler.tls.port:
  description: Port for incoming messages in the dropsonde format over tls listener
  default: 3459
doppler.tls.server_cert:
  description: TLS server certificate
  default: ""
doppler.tls.server_key:
  description: TLS server key
  default: ""
doppler.unmarshaller_count:
  description: Number of parallel unmarshallers to run within Doppler
  default: 5
doppler.use_ssl:
  description: Whether to use ssl for the doppler_logging_endpoint listed at /v2/info
  default: true
doppler.websocket_write_timeout_seconds:
  description: Interval before a websocket write is aborted if it does not succeed
  default: 60
doppler.zone:
  description: Zone of the doppler server
  default: null
doppler_endpoint.shared_secret:
  description: Shared secret used to verify cryptographically signed dropsonde messages
  default: null
env.http_proxy:
  description: The http_proxy across the VMs used for all requests over http
  default: null
env.https_proxy:
  description: The http_proxy across the VMs used for all requests over https
  default: null
env.no_proxy:
  description: Set No_Proxy across the VMs
  default: null
etcd.advertise_urls_dns_suffix:
  description: DNS suffix for all nodes in the etcd cluster
  default: null
etcd.ca_cert:
  description: PEM-encoded CA certificate
  default: null
etcd.client_cert:
  description: PEM-encoded client certificate
  default: null
etcd.client_key:
  description: PEM-encoded client key
  default: null
etcd.cluster:
  description: Information about etcd cluster
  default: null
etcd.dns_health_check_host:
  description: Host to ping for confirmation of DNS resolution
  default: consul.service.cf.internal
etcd.election_timeout_in_milliseconds:
  description: Time without receiving a heartbeat before peer should attempt to become
    leader in milliseconds. See https://coreos.com/docs/cluster-management/debugging/etcd-tuning
  default: 1000
etcd.heartbeat_interval_in_milliseconds:
  description: Interval between heartbeats in milliseconds. See https://coreos.com/docs/cluster-management/debugging/etcd-tuning
  default: 50
etcd.machines:
  description: IPs pointing to the ETCD cluster
  default: null
etcd.peer_ca_cert:
  description: PEM-encoded peer CA certificate
  default: null
etcd.peer_cert:
  description: PEM-encoded peer certificate
  default: null
etcd.peer_key:
  description: PEM-encoded peer key
  default: null
etcd.peer_require_ssl:
  description: enable ssl between etcd peers
  default: true
etcd.require_ssl:
  description: enable ssl for all communication with etcd
  default: true
etcd.server_cert:
  description: PEM-encoded server certificate
  default: null
etcd.server_key:
  description: PEM-encoded server key
  default: null
etcd_metrics_server.etcd.ca_cert:
  description: PEM-encoded CA certificate
  default: ""
etcd_metrics_server.etcd.client_cert:
  description: PEM-encoded client certificate
  default: ""
etcd_metrics_server.etcd.client_key:
  description: PEM-encoded client key
  default: ""
etcd_metrics_server.etcd.dns_suffix:
  description: |
    DNS suffix of the etcd server to instrument.
    Target etcd server must be colocated with this etcd_metrics_server.
    This property is only used if 'etcd_metrics_server.etcd.require_ssl' is 'true'."
  default: null
etcd_metrics_server.etcd.machine:
  description: |
    Address of any etcd server to instrument.
    Target etcd server does not need to be colocated with this etcd_metrics_server.
    This address must be an IP or a domain name that resolves to a single etcd server.
    This property is only used if 'etcd_metrics_server.etcd.require_ssl' is 'false'.
  default: 127.0.0.1
etcd_metrics_server.etcd.port:
  description: port of etcd server to instrument
  default: 4001
etcd_metrics_server.etcd.require_ssl:
  description: enable ssl for all communication with etcd
  default: false
etcd_metrics_server.status.password:
  description: basic auth password for metrics server (leave empty for generated)
  default: ""
etcd_metrics_server.status.port:
  description: listening port for metrics server
  default: 5678
etcd_metrics_server.status.username:
  description: basic auth username for metrics server (leave empty for generated)
  default: ""
etcd_proxy.etcd.ca_cert:
  description: etcd ca certificate
  default: ""
etcd_proxy.etcd.client_cert:
  description: etcd client certificate
  default: ""
etcd_proxy.etcd.client_key:
  description: etcd client key
  default: ""
etcd_proxy.etcd.dns_suffix:
  description: dns suffix of etcd server
  default: etcd.service.cf.internal
etcd_proxy.etcd.port:
  description: port of the etcd server
  default: 4001
etcd_proxy.port:
  description: port of proxy server
  default: 4001
etcd_testconsumer.etcd.ca_cert:
  description: PEM-encoded CA certificate
  default: ""
etcd_testconsumer.etcd.client_cert:
  description: PEM-encoded client certificate
  default: ""
etcd_testconsumer.etcd.client_key:
  description: PEM-encoded client key
  default: ""
etcd_testconsumer.etcd.dns_health_check_host:
  description: Host to ping for confirmation of DNS resolution
  default: consul.service.cf.internal
etcd_testconsumer.etcd.machines:
  description: Addresses of etcd machines
  default: null
etcd_testconsumer.etcd.require_ssl:
  description: enable ssl for all communication with etcd
  default: false
ha_proxy.buffer_size_bytes:
  description: Buffer size to use for requests, any requests larger than this (large
    cookies or query strings) will result in a gateway error
  default: 16384
ha_proxy.disable_http:
  description: Disable port 80 traffic
  default: false
ha_proxy.dontlognull:
  description: Whether to disable logging of requests with no traffic (usually load-balancer
    TCP checks)
  default: false
ha_proxy.enable_stats_socket:
  description: Whether to enable a socket that can be used to query errors and status
  default: false
ha_proxy.log_to_file:
  description: Whether to send logs to a file instead of the default syslog
  default: false
ha_proxy.ssl_ciphers:
  description: List of SSL Ciphers that are passed to HAProxy
  default: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-CBC-SHA256:ECDHE-RSA-AES256-CBC-SHA384:ECDHE-RSA-AES128-CBC-SHA:ECDHE-RSA-AES256-CBC-SHA:AES128-SHA256:AES128-SHA
ha_proxy.ssl_pem:
  description: SSL certificate (PEM file)
  default: null
haproxy.health_check_port:
  description: Load balancer in front of TCP Routers should be configured to check
    the health of TCP Router instances by establishing a TCP connection on this port
  default: 80
haproxy.request_timeout_in_seconds:
  description: Server and client timeouts in seconds
  default: 300
hm9000.ca_cert:
  description: PEM-encoded CA certificate
  default: null
hm9000.client_cert:
  description: PEM-encoded client certificate
  default: null
hm9000.client_key:
  description: PEM-encoded client key
  default: null
hm9000.desired_state_batch_size:
  description: The batch size when fetching desired state information from the CC.
  default: 5000
hm9000.etcd.ca_cert:
  description: PEM-encoded CA certificate
  default: null
hm9000.etcd.client_cert:
  description: PEM-encoded client certificate to communicate with ETCD
  default: null
hm9000.etcd.client_key:
  description: PEM-encoded client key to communicate with ETCD
  default: null
hm9000.etcd.machines:
  description: IPs pointing to the ETCD cluster
  default: null
hm9000.etcd.require_ssl:
  description: Require TLS for communication with ETCD
  default: false
hm9000.fetcher_network_timeout_in_seconds:
  description: Each API call to the CC must succeed within this timeout.
  default: 30
hm9000.port:
  description: The port to serve API requests
  default: null
hm9000.sender_message_limit:
  description: The maximum number of messages the sender should send per invocation.
  default: 60
hm9000.server_cert:
  description: PEM-encoded server certificate
  default: null
hm9000.server_key:
  description: PEM-encoded server key
  default: null
hm9000.url:
  description: URL of the hm9000 server
  default: null
logger_endpoint.port:
  description: Port for logger endpoint listed at /v2/info
  default: 443
logger_endpoint.use_ssl:
  description: Whether to use ssl for logger endpoint listed at /v2/info
  default: true
loggregator.etcd.ca_cert:
  description: PEM-encoded CA certificate
  default: ""
loggregator.etcd.machines:
  description: IPs pointing to the ETCD cluster
  default: null
loggregator.etcd.maxconcurrentrequests:
  description: Number of concurrent requests to ETCD
  default: 10
loggregator.etcd.require_ssl:
  description: Enable ssl for all communication with etcd
  default: false
loggregator.outgoing_dropsonde_port:
  description: Port for outgoing dropsonde messages
  default: 8081
loggregator.tls.ca_cert:
  description: CA root required for key/cert verification
  default: ""
loggregator.uaa.client:
  description: Doppler's client id to connect to UAA
  default: doppler
loggregator.uaa.client_secret:
  description: Doppler's client secret to connect to UAA
  default: ""
loggregator.uaa_client_id:
  description: DEPRECATED in favor of loggregator.uaa.client.
  default: ""
loggregator_acceptance_tests.admin_password:
  description: ""
  default: null
loggregator_acceptance_tests.admin_user:
  description: ""
  default: null
loggregator_acceptance_tests.login_required:
  description: ""
  default: null
loggregator_endpoint.shared_secret:
  description: ""
  default: null
loggregator_load_testing.api_url:
  description: The URL for the cloud controller API.
  default: null
loggregator_load_testing.client_id:
  description: The client ID used to authenticate the user.
  default: cf
loggregator_load_testing.client_secret:
  description: The client secret used to authenticate the user.
  default: ""
loggregator_load_testing.counter_instances:
  description: The number of instances that concurrently receive messages.
  default: 1
loggregator_load_testing.doppler_url:
  description: The URL for the doppler websocket endpoint.
  default: null
loggregator_load_testing.emitter_instances:
  description: The number of instances that concurrently emit messages.
  default: 1
loggregator_load_testing.org:
  description: The org used to push apps for loggregator load testing.
  default: null
loggregator_load_testing.password:
  description: The CF password used to push the apps and connect to the firehose.
  default: null
loggregator_load_testing.rate:
  description: The rate to emit messages (messages/second/instance).
  default: 1000
loggregator_load_testing.route_scheme:
  description: The scheme used to communicate with the cf apps.
  default: https
loggregator_load_testing.space:
  description: The space used to push apps for loggregator load testing.
  default: null
loggregator_load_testing.time:
  description: 'The time that the errand should run for (format: https://golang.org/pkg/time/#ParseDuration).'
  default: 5m
loggregator_load_testing.uaa_url:
  description: The URL for the UAA endpoint.
  default: null
loggregator_load_testing.username:
  description: The CF username used to push the apps and connect to the firehose.
  default: null
login.analytics.code:
  description: Google analytics code. If Google Analytics is desired set both login.analytics.code
    and login.analytics.domain
  default: null
login.analytics.domain:
  description: Google analytics domain. If Google Analytics is desired set both login.analytics.code
    and login.analytics.domain
  default: null
login.asset_base_url:
  description: Deprecated in favor of branding properties. Base url for static assets,
    allows custom styling of the login server.  Use '/resources/pivotal' for Pivotal
    style.
  default: /resources/oss
login.branding.company_name:
  description: This name is used on the UAA Pages and in account management related
    communication in UAA
  default: null
login.branding.footer_legal_text:
  description: This text appears on the footer of all UAA pages
  default: null
login.branding.footer_links:
  description: These links appear on the footer of all UAA pages. You may choose to
    add multiple urls for things like Support, Terms of Service etc.
  default: null
login.branding.product_logo:
  description: This is a base64 encoded PNG image which will be used as the logo on
    all UAA pages like Login, Sign Up etc.
  default: null
login.branding.square_logo:
  description: This is a base64 encoded PNG image which will be used as the favicon
    for the UAA pages
  default: null
login.enabled:
  description: whether use login as the authorization endpoint or not
  default: true
login.home_redirect:
  description: URL for configuring a custom home page
  default: null
login.idpDiscoveryEnabled:
  description: IDP Discovery should be set to true if you have configured more than
    one identity provider for UAA. The discovery relies on email domain being set
    for each additional provider
  default: false
login.links:
  description: A hash of home/passwd/signup URLS (see commented examples below)
  default: null
login.links.passwd:
  description: URL for requesting password reset
  default: /forgot_password
login.links.signup:
  description: URL for requesting to signup/register for an account
  default: /create_account
login.logout.redirect.parameter.disable:
  description: When set to false, this allows an operator to leverage an open redirect
    on the UAA (/logout.do?redirect=google.com). No open redirect enabled
  default: true
login.logout.redirect.parameter.whitelist:
  description: A list of URLs. When this list is non null, including empty, and disable=false,
    logout redirects are allowed, but limited to the whitelist URLs. If a redirect
    parameter value is not white listed, redirect will be to the default URL.
  default: null
login.logout.redirect.url:
  description: The Location of the redirect header following a logout of the the UAA
    (/logout.do).
  default: /login
login.messages:
  description: |
    A nested or flat hash of messages that the login server uses to display UI message
    This will be flattened into a java.util.Properties file. The example below will lead
    to four properties, where the key is the concatenated value delimited by dot, for example scope.tokens.read=message
  default: null
login.notifications.url:
  description: The url for the notifications service (configure to use Notifications
    Service instead of SMTP server)
  default: null
login.oauth.providers:
  description: Contains a hash of OpenID Connect/Oauth Identity Providers, the key
    will be used as the origin key for that provider, followed by key/value pairs.
    Presence of the userInfoUrl will mark it as an OpenID provider instead of OAuth.
  default: null
login.prompt.password.text:
  description: The text used to prompt for a password during login
  default: Password
login.prompt.username.text:
  description: The text used to prompt for a username during login
  default: Email
login.protocol:
  description: Scheme to use for HTTP communication (http/https)
  default: https
login.saml.entity_base_url:
  description: |
    The URL for which SAML identity providers will post assertions to.
    If set it overrides the default.
    This URL should NOT have the schema (http:// or https:// prefix in it) instead just the hostname.
    The schema is derived by #{login.protocol} property.
    The default value is #{uaa.url}.replaceFirst('uaa','login'), typically login.example.com
    The UAA will display this link in the cf --sso call if there is a SAML provider enabled.
  default: null
login.saml.entityid:
  description: |
    This is used as the SAML Service Provider Entity ID. Each zone has a unique entity ID. Zones other than
    the default zone will derive their entity ID from this setting by prefexing it with the subdomain.
  default: null
login.saml.providers:
  description: Contains a hash of SAML Identity Providers, the key is the IDP Alias,
    followed by key/value pairs. To learn more about how to setup a saml identity
    provider go to https://simplesamlphp.org
  default: null
login.saml.serviceProviderCertificate:
  description: Service provider certificate.
  default: null
login.saml.serviceProviderKey:
  description: Private key for the service provider certificate.
  default: null
login.saml.serviceProviderKeyPassword:
  description: Password to protect the service provider private key.
  default: null
login.saml.signMetaData:
  description: Global property to sign Local/SP metadata
  default: true
login.saml.signRequest:
  description: Global property to sign Local/SP requests
  default: true
login.saml.signatureAlgorithm:
  description: Signature hashing algorithm for SAML. Can be SHA1, SHA256, or SHA512.
  default: null
login.saml.socket.connectionManagerTimeout:
  description: Timeout in milliseconds for connection pooling for SAML metadata HTTP
    requests
  default: 10000
login.saml.socket.soTimeout:
  description: Read timeout in milliseconds for SAML metadata HTTP requests
  default: 10000
login.saml.wantAssertionSigned:
  description: Global property to request that external IDPs sign their SAML assertion
    before sending them to the UAA
  default: false
login.self_service_links_enabled:
  description: Enable self-service account creation and password resets links.
  default: null
login.smtp:
  description: SMTP server configuration, for password reset emails etc.
  default: null
login.smtp.auth:
  description: If true, authenticate using AUTH command. https://javamail.java.net/nonav/docs/api/com/sun/mail/smtp/package-summary.html
  default: false
login.smtp.from_address:
  description: SMTP from address
  default: null
login.smtp.host:
  description: SMTP server host address
  default: localhost
login.smtp.password:
  description: SMTP server password
  default: null
login.smtp.port:
  description: SMTP server port
  default: 2525
login.smtp.starttls:
  description: If true, send STARTTLS command before login to server. https://javamail.java.net/nonav/docs/api/com/sun/mail/smtp/package-summary.html
  default: false
login.smtp.user:
  description: SMTP server username
  default: null
login.url:
  description: |
    Set if you have an external login server.
    The UAA uses this link on by its email service to create links
    The UAA uses this as a base domain for internal hostnames so that subdomain can be detected
    This defaults to the uaa.url property, and if not set, to login.<domain>
  default: null
metron.port:
  description: The port used to emit dropsonde messages to the Metron agent.
  default: 3457
metron_agent.buffer_size:
  description: DEPRECATED
  default: 10000
metron_agent.debug:
  description: boolean value to turn on verbose mode
  default: false
metron_agent.deployment:
  description: Name of deployment (added as tag on all outgoing metrics)
  default: null
metron_agent.dropsonde_incoming_port:
  description: DEPRECATED - replaced by metron_agent.listening_port
  default: 3457
metron_agent.enable_buffer:
  description: DEPRECATED
  default: false
metron_agent.etcd.client_cert:
  description: PEM-encoded client certificate
  default: ""
metron_agent.etcd.client_key:
  description: PEM-encoded client key
  default: ""
metron_agent.listening_address:
  description: Address the metron agent is listening on to receive dropsonde log messages
    provided for BOSH links and should not be overwritten
  default: 127.0.0.1
metron_agent.listening_port:
  description: Port the metron agent is listening on to receive dropsonde log messages
  default: 3457
metron_agent.logrotate.freq_min:
  description: The frequency in minutes which logrotate will rotate VM logs
  default: 5
metron_agent.logrotate.rotate:
  description: The number of files that logrotate will keep around on the VM
  default: 7
metron_agent.logrotate.size:
  description: The size at which logrotate will decide to rotate the log file
  default: 50M
metron_agent.preferred_protocol:
  description: DEPRECATED - replaced with metron_agent.protocols
  default: udp
metron_agent.protocols:
  description: A priority list of protocols for metron to connect to doppler over.  Metron
    will refuse to connect to doppler over any protocol not in this list.
  default:
  - udp
metron_agent.tcp.batching_buffer_bytes:
  description: The number of bytes which can be buffered prior to TCP writes (applies
    to TLS over TCP)
  default: 10240
metron_agent.tcp.batching_buffer_flush_interval_milliseconds:
  description: The maximum time that a message can stay in the batching buffer before
    being flushed
  default: 100
metron_agent.tls.client_cert:
  description: TLS client certificate
  default: ""
metron_agent.tls.client_key:
  description: TLS client key
  default: ""
metron_agent.zone:
  description: Availability zone where this agent is running
  default: null
metron_endpoint.dropsonde_port:
  description: The port used to emit dropsonde messages to the Metron agent
  default: 3457
metron_endpoint.host:
  description: The host used to emit messages to the Metron agent
  default: 127.0.0.1
metron_endpoint.port:
  description: The port used to emit messages to the Metron agent
  default: 3457
metron_endpoint.shared_secret:
  description: Shared secret used to verify cryptographically signed dropsonde messages
  default: null
name:
  description: '''name'' attribute in the /v2/info endpoint'
  default: ""
nats.authorization_timeout:
  description: After accepting a connection, wait up to this many seconds for credentials.
  default: 15
nats.debug:
  description: Enable debug logging output.
  default: false
nats.machines:
  description: IPs of each NATS cluster member
  default: null
nats.monitor_port:
  description: Port for varz and connz monitoring. 0 means disabled.
  default: 0
nats.password:
  description: Password for NATS authentication
  default: null
nats.port:
  description: TCP port of NATS servers
  default: null
nats.prof_port:
  description: Port for pprof. 0 means disabled.
  default: 0
nats.trace:
  description: Enable trace logging output.
  default: false
nats.user:
  description: User name for NATS authentication
  default: null
nfs_server.address:
  description: NFS server for droplets and apps (not used in an AWS deploy, use s3
    instead)
  default: null
nfs_server.allow_from_entries:
  description: An array of Hosts, Domains, Wildcard Domains, CIDR Networks and/or
    IPs from which /var/vcap/store is accessible
  default: null
nfs_server.idmapd_domain:
  description: Domain name for NFS idmapd
  default: localdomain
nfs_server.nfsv4:
  description: bool to use NFS4 (not used in an AWS deploy, use s3 instead)
  default: null
nfs_server.no_root_squash:
  description: Exports /var/vcap/store with no_root_squash when set to true
  default: false
nfs_server.pipefs_directory:
  description: Pipefs directory for NFS idmapd
  default: /var/lib/nfs/rpc_pipefs
nfs_server.share:
  description: Path to share from the remote NFS server (not used in an AWS deploy,
    use s3 instead)
  default: null
nfs_server.share_path:
  description: The location at which to mount the nfs share
  default: /var/vcap/nfs
postgres.address:
  description: The database address
  default: null
postgres.databases:
  description: A list of databases and associated properties to create
  default: null
postgres.log_line_prefix:
  description: The postgres `printf` style string that is output at the beginning
    of each log line
  default: '%m: '
postgres.max_connections:
  description: Maximum number of database connections
  default: 500
postgres.port:
  description: The database port
  default: 5524
postgres.roles:
  description: A list of database roles and associated properties to create
  default: null
request_timeout_in_seconds:
  description: Timeout in seconds for Router -> Endpoint roundtrip.
  default: 900
route_registrar.routes:
  description: |
    * Array of hashes determining which routes will be registered.
    * Each hash should have 'port', 'uris', 'registration_interval'
      and 'name' keys.
    * 'registration_interval' is the delay between
      routing updates. It must be a time duration represented as a string
      (e.g. "10s").
      It must parse to a positive time duration i.e. "-5s" is not permitted.
    * Additionally, the 'tags' and 'health_check' keys are optional.
    * 'uris' is an array of URIs to register for the 'port'.
    * 'tags' are included in metrics that gorouter emits to support filtering.
    * 'health_check' is a hash which should have 'name' and 'script_path'.
    * 'health_check.timeout' is optional.
      If the health_check timeout is not provided, it defaults to half of the
      value of `registration_interval`.
      If it is provided it must be a time duration represented as a string (e.g. "10s"),
      and less than the value of `registration_interval`.
      It must parse to a positive time duration i.e. "-5s" is not permitted.
    * if the healthcheck is not configured, the route is continually registered.
    * if the healthcheck script exits with success, the route is registered.
    * if the healthcheck script exits with error, the route is unregistered.
    * if a timeout is configured, the healthcheck script must exit within the timeout,
      otherwise it is terminated (with `SIGKILL`) and the route is unregistered.
  default: null
router.cipher_suites:
  description: An ordered list of supported SSL cipher suites containing golang tls
    constants separated by colons The cipher suite will be chosen according to this
    order during SSL handshake
  default: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA
router.debug_address:
  description: Address at which to serve debug info
  default: 0.0.0.0:17002
router.dns_health_check_host:
  description: Host to ping for confirmation of DNS resolution, only used when Routing
    API is enabled
  default: consul.service.cf.internal
router.drain_wait:
  description: |
    Delay in seconds after drain begins before server stops listening.
    During this time the server will respond with 503 Service Unavailable to
    requests having header
    User-Agent: {Value of router.healthcheck_user_agent}.
    This accommodates requests in transit sent during the time the health
    check responded with `ok`.
  default: 0
router.enable_access_log_streaming:
  description: 'Enables streaming of access log to syslog. Warning: this comes with
    a performance cost; due to higher I/O, max request rate is reduced.'
  default: false
router.enable_proxy:
  description: Enables support for the popular PROXY protocol, allowing downstream
    load balancers that do not support HTTP to pass along client information.
  default: false
router.enable_ssl:
  description: Enable ssl termination on the router
  default: false
router.extra_headers_to_log:
  description: A list of headers that log events will be annotated with
  default: []
router.healthcheck_user_agent:
  description: User-Agent for the health check agent (usually the Load Balancer).
  default: HTTP-Monitor/1.1
router.load_balancer_healthy_threshold:
  description: ""
  default: 20
router.logging_level:
  description: Log level for router
  default: info
router.logrotate.freq_min:
  description: The frequency in minutes which logrotate will rotate VM logs
  default: 5
router.logrotate.rotate:
  description: The number of files that logrotate will keep around on the VM
  default: 7
router.logrotate.size:
  description: The size at which logrotate will decide to rotate the log file
  default: 2M
router.number_of_cpus:
  description: Number of CPUs to utilize, the default (-1) will equal the number of
    available CPUs
  default: -1
router.offset:
  description: ""
  default: 0
router.port:
  description: Listening Port for Router.
  default: 80
router.requested_route_registration_interval_in_seconds:
  description: On startup, the router will delay listening for requests by this duration
    to increase likelihood that it has a complete routing table before serving requests.
    The router also broadcasts the same duration as a recommended interval to registering
    clients via NATS.
  default: 20
router.route_services_recommend_https:
  description: Route Services are told where to send requests after processing using
    the X-CF-Forwarded-Url header. When this property is true, the scheme for this
    URL is https. When false, the scheme is http. As requests from Route Services
    to applications on CF transit load balancers and gorouter, disable this property
    for deployments that have TLS termination disabled.
  default: true
router.route_services_secret:
  description: Support for route services is disabled when no value is configured.
    A robust passphrase is recommended.
  default: ""
router.route_services_secret_decrypt_only:
  description: To rotate keys, add your new key here and deploy. Then swap this key
    with the value of route_services_secret and deploy again.
  default: ""
router.route_services_timeout:
  description: Expiry time of a route service signature in seconds
  default: 60
router.secure_cookies:
  description: Set secure flag on http cookies
  default: false
router.servers:
  description: Array of router IPs
  default: []
router.ssl_cert:
  description: The public ssl cert for ssl termination
  default: ""
router.ssl_key:
  description: The private ssl key for ssl termination
  default: ""
router.ssl_skip_validation:
  description: Skip SSL client cert validation
  default: false
router.status.password:
  description: Password for HTTP basic auth to the varz/status endpoint.
  default: null
router.status.port:
  description: Port for the Router varz/status endpoint.
  default: 8080
router.status.user:
  description: Username for HTTP basic auth to the varz/status endpoint.
  default: null
router.suspend_pruning_if_nats_unavailable:
  description: |
    Suspend pruning of routes when NATs is unavailable and maintain the
    current routing table. WARNING: This strategy favors availability over
    consistency and there is a possibility of routing to an incorrect
    endpoint in the case of port re-use. To be used with caution."
  default: false
router.trace_key:
  description: If the X-Vcap-Trace request header is set and has this value, trace
    headers are added to the response.
  default: 22
router.tracing.enable_zipkin:
  description: Enables the addition of the X-B3-Trace-Id header to incoming requests.
    If the header already exists on the incoming request, it will not be overwritten.
  default: false
router_configurer.debug_address:
  description: Address at which to serve debug info
  default: 0.0.0.0:17002
router_configurer.log_level:
  description: Log level
  default: info
router_configurer.oauth_secret:
  description: OAuth client secret used to obtain token for Routing API from UAA.
  default: null
router_configurer.tcp_stats_collection_interval:
  description: 'String representing interval for collecting statistic metrics from
    tcp proxy. Units: ms, s, m h'
  default: 1m
routing_api.auth_disabled:
  description: auth disabled setting of routing api
  default: false
routing_api.debug_address:
  description: Address at which to serve debug info
  default: 0.0.0.0:17002
routing_api.enabled:
  description: When enabled, GoRouter will fetch HTTP routes from the Routing API
    in addition to routes obtained via NATS.
  default: false
routing_api.etcd.ca_cert:
  description: Certificate authority used to sign cert hosted by etcd
  default: ""
routing_api.etcd.client_cert:
  description: Client certificate for communication between clients and etcd
  default: ""
routing_api.etcd.client_key:
  description: Client key for communication between clients and etcd
  default: ""
routing_api.etcd.require_ssl:
  description: etcd requires client to communicate via TLS
  default: false
routing_api.etcd.servers:
  description: Must be the internal DNS name for the etcd cluster when require_ssl:true.
    When require_ssl:false either a DNS name or an array of IP addresses is supported.
  default: null
routing_api.lock_retry_interval:
  description: interval to wait before retrying a failed lock acquisition
  default: 5s
routing_api.lock_ttl:
  description: TTL for service lock
  default: 10s
routing_api.log_level:
  description: Log level
  default: info
routing_api.max_ttl:
  description: String representing the maximum TTL a client can request for route
    registration.
  default: 120s
routing_api.metrics_reporting_interval:
  description: 'String representing interval for reporting the following metrics:
    total_http_subscriptions, total_http_routes, total_tcp_subscriptions, total_tcp_routes,
    total_token_errors, key_refresh_events. Units: ms, s, m h'
  default: 30s
routing_api.port:
  description: Port on which Routing API is running.
  default: 3000
routing_api.router_groups:
  description: 'Array of router groups that will be seeded into routing_api database.
    Once some value is included with a deploy, subsequent changes to this property
    will be ignored. TCP Routing requires a router group of type: tcp.'
  default: []
routing_api.sqldb.host:
  description: Host for SQL database
  default: null
routing_api.sqldb.password:
  description: Password used for connecting to SQL database
  default: null
routing_api.sqldb.port:
  description: Port on which SQL database is listening
  default: null
routing_api.sqldb.schema:
  description: Database name for routing api
  default: null
routing_api.sqldb.type:
  description: Type of SQL database
  default: null
routing_api.sqldb.username:
  description: Username used for connecting to SQL database
  default: null
routing_api.statsd_client_flush_interval:
  description: Buffered statsd client flush interval
  default: 300ms
routing_api.statsd_endpoint:
  description: 'The endpoint for the statsd server used to translate the following
    metrics from statsd to dropsonde: total_http_subscriptions, total_http_routes,
    total_tcp_subscriptions, total_tcp_routes, total_token_errors, key_refresh_events.'
  default: localhost:8125
routing_api.system_domain:
  description: Domain reserved for CF operator; base URL where the UAA, Cloud Controller,
    and other non-user apps listen
  default: null
skip_ssl_validation:
  description: Skip TLS verification when talking to UAA
  default: false
smoke_tests.api:
  description: The Elastic Runtime API endpoint URL
  default: null
smoke_tests.apps_domain:
  description: The Elastic Runtime Application Domain
  default: null
smoke_tests.backend:
  description: Defines the backend to be used. ('dea', 'diego', '' (default))
  default: ""
smoke_tests.cf_dial_timeout_in_seconds:
  description: Sets the cli timeout (CF_DIAL_TIMEOUT)
  default: null
smoke_tests.enable_windows_tests:
  description: Toggles a portion of the suite that exercises Windows platform support
  default: false
smoke_tests.ginkgo_opts:
  description: Ginkgo options for the smoke tests
  default: ""
smoke_tests.logging_app:
  description: The Elastic Runtime app name to use when running logging tests
  default: ""
smoke_tests.org:
  description: The Elastic Runtime organization name to use when running tests
  default: null
smoke_tests.password:
  description: The Elastic Runtime API user's password
  default: null
smoke_tests.runtime_app:
  description: The Elastic Runtime app name to use when running runtime tests
  default: ""
smoke_tests.skip_ssl_validation:
  description: Toggles cli verification of the Elastic Runtime API SSL certificate
  default: false
smoke_tests.space:
  description: The Elastic Runtime space name to use when running tests
  default: null
smoke_tests.suite_name:
  description: A token used by the tests when creating Apps / Spaces
  default: CF_SMOKE_TESTS
smoke_tests.use_existing_org:
  description: Toggles setup and cleanup of the Elastic Runtime organization
  default: false
smoke_tests.use_existing_space:
  description: Toggles setup and cleanup of the Elastic Runtime space
  default: false
smoke_tests.user:
  description: The Elastic Runtime API user
  default: null
ssl.skip_cert_verify:
  description: When connecting over https, ignore bad ssl certificates
  default: false
statsd_injector.log_level:
  description: The log level for the statsd injector
  default: info
statsd_injector.metron_port:
  description: The port on which metron is running
  default: 3457
statsd_injector.statsd_port:
  description: The port on which the injector should listen for statsd messages
  default: 8125
support_address:
  description: '''support'' attribute in the /v2/info endpoint'
  default: ""
syslog_daemon_config.address:
  description: IP address for syslog aggregator
  default: null
syslog_daemon_config.custom_rule:
  description: Custom rule for syslog forward daemon
  default: ""
syslog_daemon_config.enable:
  description: Enable or disable rsyslog configuration for forwarding syslog messages
    into metron
  default: true
syslog_daemon_config.fallback_addresses:
  description: 'Addresses of fallback servers to be used if the primary syslog server
    is down. Only tcp or relp are supported. Each list entry should consist of "address",
    "transport" and "port" keys. '
  default: []
syslog_daemon_config.max_message_size:
  description: maximum message size to be sent
  default: 4k
syslog_daemon_config.port:
  description: TCP port of syslog aggregator
  default: null
syslog_daemon_config.transport:
  description: Transport to be used when forwarding logs (tcp|udp|relp).
  default: tcp
syslog_drain_binder.debug:
  description: Boolean value to turn on verbose logging for syslog_drain_binder
  default: false
syslog_drain_binder.drain_url_ttl_seconds:
  description: Time to live for drain urls in seconds
  default: 60
syslog_drain_binder.etcd.client_cert:
  description: PEM-encoded client certificate
  default: ""
syslog_drain_binder.etcd.client_key:
  description: PEM-encoded client key
  default: ""
syslog_drain_binder.locked_memory_limit:
  description: Size (KB) of shell's locked memory limit. Set to 'kernel' to use the
    kernel's default. Non-numeric values other than 'kernel', 'soft', 'hard', and
    'unlimited' will result in an error.
  default: unlimited
syslog_drain_binder.polling_batch_size:
  description: Batch size for the poll from cloud controller
  default: 1000
syslog_drain_binder.update_interval_seconds:
  description: Interval on which to poll cloud controller in seconds
  default: 15
system_domain:
  description: Domain reserved for CF operator, base URL where the login, uaa, and
    other non-user apps listen
  default: null
system_domain_organization:
  description: An organization that will be created as part of the seeding process.
    When the system_domain is not shared with (in the list of) app_domains, this is
    required as the system_domain will be created as a PrivateDomain in this organization.
  default: ""
tcp_emitter.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
tcp_emitter.bbs.client_key:
  description: PEM-encoded client key
  default: null
tcp_emitter.debug_address:
  description: Address at which to serve debug info
  default: 0.0.0.0:17002
tcp_emitter.lock_retry_interval:
  description: interval to wait before retrying a failed lock acquisition
  default: 5s
tcp_emitter.lock_ttl:
  description: TTL for service lock
  default: 10s
tcp_emitter.log_level:
  description: Log level
  default: info
tcp_emitter.oauth_secret:
  description: Password for UAA client for tcp emitter.
  default: null
tcp_emitter.route_ttl:
  description: TTL used for routes registered with Routing API.
  default: 120s
tcp_emitter.sync_interval:
  description: Interval to sync with BBS to get latest route information.
  default: 60s
traffic_controller.debug:
  description: boolean value to turn on verbose logging for loggregator system (dea
    agent & loggregator server)
  default: false
traffic_controller.disable_access_control:
  description: Traffic controller bypasses authentication with the UAA and CC
  default: false
traffic_controller.etcd.client_cert:
  description: PEM-encoded client certificate
  default: ""
traffic_controller.etcd.client_key:
  description: PEM-encoded client key
  default: ""
traffic_controller.locked_memory_limit:
  description: Size (KB) of shell's locked memory limit. Set to 'kernel' to use the
    kernel's default. Non-numeric values other than 'kernel', 'soft', 'hard', and
    'unlimited' will result in an error.
  default: unlimited
traffic_controller.outgoing_port:
  description: DEPRECATED
  default: 8080
traffic_controller.security_event_logging.enabled:
  description: Enable logging of all requests made to the Traffic Controller in CEF
    format
  default: false
uaa.admin.client_secret:
  description: Secret of the admin client - a client named admin with uaa.admin as
    an authority
  default: null
uaa.authentication.policy.countFailuresWithinSeconds:
  description: Number of seconds in which lockoutAfterFailures failures must occur
    in order for account to be locked
  default: 1200
uaa.authentication.policy.global.countFailuresWithinSeconds:
  description: Number of seconds in which lockoutAfterFailures failures must occur
    in order for account to be locked
  default: 3600
uaa.authentication.policy.global.lockoutAfterFailures:
  description: Number of allowed failures before account is locked
  default: 5
uaa.authentication.policy.global.lockoutPeriodSeconds:
  description: Number of seconds to lock out an account when lockoutAfterFailures
    failures is exceeded
  default: 300
uaa.authentication.policy.lockoutAfterFailures:
  description: Number of allowed failures before account is locked
  default: 5
uaa.authentication.policy.lockoutPeriodSeconds:
  description: Number of seconds to lock out an account when lockoutAfterFailures
    failures is exceeded
  default: 300
uaa.ca_cert:
  description: ""
  default: ""
uaa.catalina_opts:
  description: The options used to configure Tomcat
  default: -Xmx768m -XX:MaxMetaspaceSize=256m
uaa.cc.token_secret:
  description: Symmetric secret used to decode uaa tokens. Used for testing.
  default: null
uaa.clients:
  description: List of OAuth2 clients that the UAA will be bootstrapped with
  default: null
uaa.clients.cc-service-dashboards.scope:
  description: Used to grant scope for SSO clients for service brokers
  default: openid,cloud_controller_service_permissions.read
uaa.clients.cc-service-dashboards.secret:
  description: Used for generating SSO clients for service brokers.
  default: null
uaa.clients.cc_routing.secret:
  description: Used for fetching routing information from the Routing API
  default: null
uaa.clients.cc_service_broker_client.scope:
  description: (DEPRECATED) - Used to grant scope for SSO clients for service brokers
  default: openid,cloud_controller_service_permissions.read
uaa.clients.cc_service_broker_client.secret:
  description: (DEPRECATED) - Used for generating SSO clients for service brokers.
  default: null
uaa.clients.cloud_controller_username_lookup.secret:
  description: Used for fetching usernames from UAA.
  default: null
uaa.clients.doppler.secret:
  description: DEPRECATED in favor of loggregator.uaa.client_secret.
  default: ""
uaa.clients.gorouter.secret:
  description: Password for UAA client for the gorouter.
  default: null
uaa.database.abandoned_timeout:
  description: Timeout in seconds for the longest running queries. Take into DB migrations
    for this timeout as they may run during a long period of time.
  default: 300
uaa.database.case_insensitive:
  description: Set to true if you don't want to be using LOWER() SQL functions in
    search queries/filters, because you know that your DB is case insensitive. If
    this property is null, then it will be set to true if the UAA DB is MySQL and
    false otherwise, but even on MySQL you can override it by setting it explicitly
    to false
  default: null
uaa.database.log_abandoned:
  description: Should connections that are forcibly closed be logged.
  default: true
uaa.database.max_connections:
  description: The max number of open connections to the DB from a running UAA instance
  default: 100
uaa.database.max_idle_connections:
  description: The max number of open idle connections to the DB from a running UAA
    instance
  default: 10
uaa.database.min_idle_connections:
  description: The min number of open idle connections to the DB from a running UAA
    instance
  default: 0
uaa.database.remove_abandoned:
  description: True if connections that are left open longer then abandoned_timeout
    seconds during a session(time between borrow and return from pool) should be forcibly
    closed
  default: false
uaa.disableInternalAuth:
  description: Disables internal user authentication
  default: false
uaa.disableInternalUserManagement:
  description: Disables UI and API for internal user management
  default: false
uaa.issuer:
  description: The url to use as the issuer URI
  default: null
uaa.jwt.claims.exclude:
  description: List of claims to exclude from the JWT-based OAuth2 tokens
  default: null
uaa.jwt.policy.accessTokenValiditySeconds:
  description: The access token validity for the default zone if nothing is configured
    on the client. Will override global validity policies for the default zone only.
  default: 43200
uaa.jwt.policy.active_key_id:
  description: The ID of the JWT signing key to be used when signing tokens.
  default: null
uaa.jwt.policy.global.accessTokenValiditySeconds:
  description: The global access token validity for all zones if nothing is configured
    on the client
  default: 43200
uaa.jwt.policy.global.refreshTokenValiditySeconds:
  description: The global refresh token validity for all zones if nothing is configured
    on the client
  default: 2592000
uaa.jwt.policy.keys:
  description: Map of key IDs and signing keys, each defined with a property `signingKey`
  default: null
uaa.jwt.policy.refreshTokenValiditySeconds:
  description: The refresh token validity for the default zone if nothing is configured
    on the client. Will override global validity policies for the default zone only.
  default: 2592000
uaa.jwt.refresh.restrict_grant:
  description: Disallows refresh-token grant for any client for which the user has
    not approved the `uaa.offline_token` scope
  default: false
uaa.jwt.revocable:
  description: Set to true if you wish that even JWT tokens become individually revocable
    and stored in the UAA token storage. This setting applies to the default zone
    only.
  default: false
uaa.jwt.signing_key:
  description: Deprecated. Use uaa.jwt.policy.keys. The key used to sign the JWT-based
    OAuth2 tokens
  default: null
uaa.jwt.verification_key:
  description: Deprecated. Use uaa.jwt.policy.keys. The key used to verify JWT-based
    OAuth2 tokens
  default: null
uaa.ldap.add_shadow_user_on_login:
  description: If set to false, only users pre-populated in the UAA user database
    will be allowed to authenticate via LDAP. If set to true, any user from LDAP will
    be allowed to authenticate and an internal user will be created if one does not
    yet exist.
  default: true
uaa.ldap.attributeMappings:
  description: Specifies how UAA user attributes map to LDAP attributes. given_name,
    family_name, and phone_number are UAA user attributes, while other attributes
    should be included using the prefix `user.attribute`
  default: null
uaa.ldap.emailDomain:
  description: Sets the whitelist of emails domains that the LDAP identity provider
    handles
  default: null
uaa.ldap.enabled:
  description: Set to true to enable LDAP
  default: false
uaa.ldap.externalGroupsWhitelist:
  description: Whitelist of external groups from LDAP that get added as roles in the
    ID Token
  default: null
uaa.ldap.groups.groupRoleAttribute:
  description: Used with groups-as-scopes, defines the attribute that holds the scope
    name(s).
  default: spring.security.ldap.dn
uaa.ldap.groups.groupSearchFilter:
  description: Search query filter to find the groups a user belongs to, or for a
    nested search, groups that a group belongs to
  default: member={0}
uaa.ldap.groups.maxSearchDepth:
  description: Set to number of levels a nested group search should go. Set to 1 to
    disable nested groups (default)
  default: "1"
uaa.ldap.groups.profile_type:
  description: 'What type of group integration should be used. Values are: ''no-groups'',
    ''groups-as-scopes'', ''groups-map-to-scopes'''
  default: no-groups
uaa.ldap.groups.searchBase:
  description: Search start point for a user group membership search
  default: ""
uaa.ldap.groups.searchSubtree:
  description: Boolean value, set to true to search below the search base
  default: "true"
uaa.ldap.localPasswordCompare:
  description: Used with search-and-compare only. Set to true if passwords are retrieved
    by the search, and should be compared in the login server.
  default: "true"
uaa.ldap.mailAttributeName:
  description: The name of the LDAP attribute that contains the users email address
  default: mail
uaa.ldap.mailSubstitute:
  description: Defines an email pattern containing a {0} to generate an email address
    for an LDAP user during authentication
  default: ""
uaa.ldap.mailSubstituteOverridesLdap:
  description: Set to true if you wish to override an LDAP user email address with
    a generated one
  default: false
uaa.ldap.passwordAttributeName:
  description: Used with search-and-compare only. The name of the password attribute
    in the LDAP directory
  default: userPassword
uaa.ldap.passwordEncoder:
  description: Used with search-and-compare only. The encoder used to properly encode
    user password to match the one in the LDAP directory.
  default: org.cloudfoundry.identity.uaa.ldap.DynamicPasswordComparator
uaa.ldap.profile_type:
  description: 'The file to be used for configuring the LDAP authentication. Options
    are: ''simple-bind'', ''search-and-bind'', ''search-and-compare'''
  default: search-and-bind
uaa.ldap.referral:
  description: |
    Configures the UAA LDAP referral behavior. The following values are possible:
    - follow -> Referrals are followed
    - ignore -> Referrals are ignored and the partial result is returned
    - throw  -> An error is thrown and the authentication is aborted
    Reference: http://docs.oracle.com/javase/jndi/tutorial/ldap/referral/jndi.html
  default: follow
uaa.ldap.searchBase:
  description: Used with search-and-bind and search-and-compare. Define a base where
    the search starts at.
  default: ""
uaa.ldap.searchFilter:
  description: Used with search-and-bind and search-and-compare. Search filter used.
    Takes one parameter, user ID defined as {0}
  default: cn={0}
uaa.ldap.ssl.skipverification:
  description: Set to true, and LDAPS connection will not validate the server certificate.
  default: false
uaa.ldap.ssl.tls:
  description: If using StartTLS, what mode to enable. Default is none, not enabled.
    Possible values are none, simple, external
  default: none
uaa.ldap.sslCertificate:
  description: Used with ldaps:// URLs. The certificate, if self signed, to be trusted
    by this connection.
  default: null
uaa.ldap.sslCertificateAlias:
  description: Used with ldaps:// URLs. The certificate alias, to be trusted by this
    connection and stored in the keystore.
  default: null
uaa.ldap.url:
  description: The URL to the ldap server, must start with ldap:// or ldaps://. Allows
    multiple servers to be specified, space separated
  default: null
uaa.ldap.userDN:
  description: 'Used with search-and-bind and search-and-compare. A valid LDAP ID
    that has read permissions to perform a search of the LDAP tree for user information. '
  default: null
uaa.ldap.userDNPattern:
  description: Used with simple-bind only. A semi-colon separated lists of DN patterns
    to construct a DN direct from the user ID without performing a search.
  default: null
uaa.ldap.userDNPatternDelimiter:
  description: The delimiter character in between user DN patterns for simple-bind
    authentication
  default: ;
uaa.ldap.userPassword:
  description: Used with search-and-bind and search-and-compare. Password for the
    LDAP ID that performs a search of the LDAP tree for user information.
  default: null
uaa.logging_level:
  description: Set UAA logging level.  (e.g. TRACE, DEBUG, INFO)
  default: DEBUG
uaa.logging_use_rfc3339:
  description: Sets the time format for log messages to be yyyy-MM-dd'T'HH:mm:ss.SSSXXX
    instead of yyyy-MM-dd HH:mm:ss.SSS
  default: false
uaa.login.client_secret:
  description: Default login client secret, if no login client is defined
  default: null
uaa.newrelic:
  description: |
    To enable newrelic monitoring, the sub element of this property will be placed in
    a configuration file called newrelic.yml in the jobs config directory.
    The syntax that must adhere to documentation in https://docs.newrelic.com/docs/agents/java-agent/configuration/java-agent-configuration-config-file
    The JVM option -javaagent:/path/to/newrelic.jar will be added to Apache Tomcat's startup script
    The enablement of the NewRelic agent in the UAA is triggered by the property uaa.newrelic.common.license_key
    The property uaa.newrelic.common.license_key must be set!
  default: null
uaa.password.policy.expirePasswordInMonths:
  description: Number of months after which current password expires
  default: 0
uaa.password.policy.global.expirePasswordInMonths:
  description: Number of months after which current password expires
  default: 0
uaa.password.policy.global.maxLength:
  description: Maximum number of characters required for password to be considered
    valid
  default: 255
uaa.password.policy.global.minLength:
  description: Minimum number of characters required for password to be considered
    valid
  default: 0
uaa.password.policy.global.requireDigit:
  description: Minimum number of digits required for password to be considered valid
  default: 0
uaa.password.policy.global.requireLowerCaseCharacter:
  description: Minimum number of lowercase characters required for password to be
    considered valid
  default: 0
uaa.password.policy.global.requireSpecialCharacter:
  description: Minimum number of special characters required for password to be considered
    valid
  default: 0
uaa.password.policy.global.requireUpperCaseCharacter:
  description: Minimum number of uppercase characters required for password to be
    considered valid
  default: 0
uaa.password.policy.maxLength:
  description: Maximum number of characters required for password to be considered
    valid
  default: 255
uaa.password.policy.minLength:
  description: Minimum number of characters required for password to be considered
    valid
  default: 0
uaa.password.policy.requireDigit:
  description: Minimum number of digits required for password to be considered valid
  default: 0
uaa.password.policy.requireLowerCaseCharacter:
  description: Minimum number of lowercase characters required for password to be
    considered valid
  default: 0
uaa.password.policy.requireSpecialCharacter:
  description: Minimum number of special characters required for password to be considered
    valid
  default: 0
uaa.password.policy.requireUpperCaseCharacter:
  description: Minimum number of uppercase characters required for password to be
    considered valid
  default: 0
uaa.port:
  description: Port that uaa will accept connections on
  default: 8080
uaa.proxy.servers:
  description: Array of the router IPs acting as the first group of HTTP/TCP backends.
    These will be added to the proxy_ips_regex as exact matches.
  default: []
uaa.proxy_ips_regex:
  description: |
    A pipe delimited set of regular expressions of IP addresses that are considered reverse proxies.
    When a request from these IP addresses come in, the x-forwarded-for and x-forwarded-proto headers will be respected.
    If the uaa.restricted_ips_regex is set, it will be appended to this list for backwards compatibility purposes.
  default: 10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.1[6-9]{1}\.\d{1,3}\.\d{1,3}|172\.2[0-9]{1}\.\d{1,3}\.\d{1,3}|172\.3[0-1]{1}\.\d{1,3}\.\d{1,3}
uaa.require_https:
  description: Request came in on a secure connection. Expect the load balancer/proxy
    to set the proper headers (x-forwarded-for, x-forwarded-proto)
  default: true
uaa.scim.external_groups:
  description: |
    External group mappings. Either formatted as an OpenStruct.
    As an OpenStruct, the mapping additionally specifies an origin to which the mapping is applied:
      origin1:
        external_group1:
          - internal_group1
          - internal_group2
          - internal_group3
        external_group2:
          - internal_group2
          - internal_group4
      origin2:
        external_group3:
          - internal_group3
          - internal_group4
          - internal_group5
  default: null
uaa.scim.groups:
  description: |
    Contains a hash of group names and their descriptions. These groups will be added to the UAA database for the default zone but not associated with any user.
    Example:
      uaa:
        scim:
          groups:
            my-test-group: 'My test group description'
            another-group: 'Another group description'
  default: null
uaa.scim.user.override:
  description: If true override users defined in uaa.scim.users found in the database.
  default: true
uaa.scim.userids_enabled:
  description: Enables the endpoint `/ids/Users` that allows consumers to translate
    user ids to name
  default: true
uaa.scim.users:
  description: |
    A list of users to be bootstrapped with authorities.
    Each entry supports the following format:
      Short OpenStruct:
        - name: username
          password: password
          groups:
            - group1
            - group2
      Long OpenStruct:
        - name: username
          password: password
          groups:
            - group1
            - group2
          firstName: first name
          lastName: lastName
          email: email
          origin: origin-value - most commonly uaa
  default: null
uaa.servlet.session-cookie:
  description: |
    Optional configuration of the UAA session cookie.
    Defaults are the following key value pairs:
      secure: <(boolean)this value if set, otherwise require_https>
      http-only: <(boolean) - default to true. set HttpOnly flag on cookie.
      max-age: <(int) lifetime in seconds of cookie - default to 30 minutes)
      name: <(String) name of cookie, default is JSESSIONID>
      comment: <(String) optional comment in cookie>
      path: <(String) path for cookie, default is />
      domain: <(String) domain for cookie, default is incoming request domain>
  default: null
uaa.ssl.port:
  description: If this property Tomcat will listen to this port and expect https traffic.
    If null, tomcat will not listen to this port
  default: 8443
uaa.ssl.protocol_header:
  description: The header to look for to determine if ssl termination was performed
    by a front end load balancer.
  default: x-forwarded-proto
uaa.sslCertificate:
  description: The server's ssl certificate. The default is a self-signed certificate
    and should always be replaced for production deployments
  default: ""
uaa.sslPrivateKey:
  description: The server's ssl private key. Only passphrase-less keys are supported
  default: ""
uaa.tls_port:
  description: Port on which UAA is listening for TLS connections. This is required
    for obtaining a OAuth token for Routing API.
  default: null
uaa.url:
  description: The base url of the UAA
  default: null
uaa.user.authorities:
  description: Contains a list of the default authorities/scopes assigned to a user
  default:
  - openid
  - scim.me
  - cloud_controller.read
  - cloud_controller.write
  - cloud_controller_service_permissions.read
  - password.write
  - uaa.user
  - approvals.me
  - oauth.approvals
  - notification_preferences.read
  - notification_preferences.write
  - profile
  - roles
  - user_attributes
  - uaa.offline_token
uaa.zones.internal.hostnames:
  description: |
    A list of hostnames that are routed to the UAA, specifically the default zone in the UAA. The UAA will reject any Host headers that it doesn't recognize.
    By default the UAA recognizes:
      The hostname from the property uaa.url
      The hostname from the property login.url
      localhost (in order to accept health checks)
    Any hostnames added as a list are additive to the default hostnames allowed.
  default: null
uaadb.address:
  description: The UAA database IP address
  default: null
uaadb.databases:
  description: The list of databases used in UAA database including tag/name
  default: null
uaadb.db_scheme:
  description: Database scheme for UAA DB
  default: null
uaadb.port:
  description: The UAA database Port
  default: null
uaadb.roles:
  description: The list of database Roles used in UAA database including tag/name/password
  default: null
version:
  description: '''version'' attribute in the /v2/info endpoint'
  default: 0
