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
acceptance_tests.binary_buildpack_name:
  description: The name of the binary buildpack to use in acceptance tests that specify
    a buildpack.
  default: null
acceptance_tests.broker_start_timeout:
  description: Timeout for broker starts
  default: null
acceptance_tests.cf_push_timeout:
  description: Timeout for cf push
  default: null
acceptance_tests.client_secret:
  description: The client secret for the uaa gorouter client
  default: null
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
acceptance_tests.include_internet_dependent:
  description: Flag to include the internet dependent test suite.
  default: false
acceptance_tests.include_logging:
  description: Flag to include the logging test suite.
  default: false
acceptance_tests.include_operator:
  description: Flag to include the operator tests which may modify the global state
    of an Elastic Runtime deployment.
  default: false
acceptance_tests.include_route_services:
  description: Flag to include the route services tests. Diego must be deployed for
    these tests to pass.
  default: false
acceptance_tests.include_routing:
  description: Flag to include the routing test suite.
  default: false
acceptance_tests.include_security_groups:
  description: Flag to include the security groups test suite.
  default: false
acceptance_tests.include_services:
  description: Flag to include the services API test suite.
  default: false
acceptance_tests.include_sso:
  description: Flag to include the services tests that integrate with SSO.
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
  default: 2
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
acceptance_tests.skip_diego_unsupported_tests:
  description: Skip tests that are known to not be supported by Diego. Set to true
    if your deployment defaults to Diego as its runtime.
  default: false
acceptance_tests.skip_regex:
  description: Regex for tests that should be skipped
  default: null
acceptance_tests.skip_ssl_validation:
  description: Toggles cli verification of the Elastic Runtime API SSL certificate
  default: false
acceptance_tests.staticfile_buildpack_name:
  description: The name of the staticfile buildpack to use in acceptance tests that
    specify a buildpack.
  default: null
acceptance_tests.system_domain:
  description: The system domain for your CF release
  default: null
acceptance_tests.use_diego:
  description: App tests push their apps using diego if enabled. Route service tests
    require this flag to run.
  default: false
acceptance_tests.use_http:
  description: Flag for using HTTP when making api and application requests rather
    than the default HTTPS
  default: false
acceptance_tests.verbose:
  description: Whether to pass the -v flag to cf-acceptance-tests
  default: false
app_domains:
  description: 'Array of domains for user apps (example: ''user.app.space.foo'', a
    user app called ''neat'' will listen at ''http://neat.user.app.space.foo'')'
  default: null
app_ssh.host_key_fingerprint:
  description: Fingerprint of the host key of the SSH proxy that brokers connections
    to application instances
  default: null
app_ssh.oauth_client_id:
  description: The oauth client ID of the SSH proxy
  default: ssh-proxy
app_ssh.port:
  description: External port for SSH access to application instances
  default: 2222
build:
  description: ""
  default: "2222"
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
cc.buildpacks.fog_connection:
  description: Fog connection hash
  default: null
cc.bulk_api_password:
  description: password for the bulk api
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
cc.db_encryption_key:
  description: key for encrypting sensitive values in the CC database
  default: ""
cc.db_logging_level:
  description: Log level for cc database operations
  default: debug2
cc.default_app_disk_in_mb:
  description: The default disk space an app gets
  default: 1024
cc.default_app_memory:
  description: How much memory given to an app if not specified
  default: 1024
cc.default_fog_connection.local_root:
  description: Local root when fog provider is not overridden (should be an NFS mount
    if using more than one cloud controller)
  default: /var/vcap/nfs/shared
cc.default_fog_connection.provider:
  description: Local fog provider (should always be 'Local'), used if fog_connection
    hash is not provided in the manifest
  default: Local
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
cc.droplets.fog_connection:
  description: Fog connection hash
  default: null
cc.droplets.max_staged_droplets_stored:
  description: Number of recent, staged droplets stored per app (not including current
    droplet)
  default: 5
cc.external_host:
  description: Host part of the cloud_controller api URI, will be joined with value
    of 'domain'
  default: api
cc.external_port:
  description: External Cloud Controller port
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
cc.info.build:
  description: build attribute in the /info endpoint
  default: null
cc.info.custom:
  description: Custom values for /v2/info endpoint
  default: null
cc.info.description:
  description: free form description for attribute in the /info endpoint
  default: null
cc.info.name:
  description: name attribute in the /info endpoint
  default: null
cc.info.version:
  description: version attribute in the /info endpoint
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
  default: debug2
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
  description: ""
  default: error
cc.packages.app_package_directory_key:
  description: Directory (bucket) used store app packages.  It does not have be pre-created.
  default: cc-packages
cc.packages.cdn.key_pair_id:
  description: Key pair name for signed download URIs
  default: ""
cc.packages.cdn.private_key:
  description: Private key for signing download URIs
  default: ""
cc.packages.cdn.uri:
  description: URI for a CDN to used for app package downloads
  default: ""
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
cc.resource_pool.cdn.key_pair_id:
  description: Key pair name for signed download URIs
  default: ""
cc.resource_pool.cdn.private_key:
  description: Private key for signing download URIs
  default: ""
cc.resource_pool.cdn.uri:
  description: URI for a CDN to used for resource pool downloads
  default: ""
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
cc.thresholds.api.alert_if_above_mb:
  description: The cc will alert if memory remains above this threshold for 3 monit
    cycles
  default: 2250
cc.thresholds.api.restart_if_above_mb:
  description: The cc will restart if memory remains above this threshold for 3 monit
    cycles
  default: 2450
cc.thresholds.api.restart_if_consistently_above_mb:
  description: The cc will restart if memory remains above this threshold for 15 monit
    cycles
  default: 2250
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
ccdb.address:
  description: ""
  default: null
ccdb.databases:
  description: ""
  default: null
ccdb.db_scheme:
  description: ""
  default: postgres
ccdb.max_connections:
  description: Maximum connections for Sequel
  default: 25
ccdb.pool_timeout:
  description: ""
  default: 10
ccdb.port:
  description: ""
  default: null
ccdb.roles:
  description: ""
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
consul.agent.datacenter:
  description: Name of the agent's datacenter.
  default: dc1
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
consul.agent.sync_timeout_in_seconds:
  description: Time to wait for a consul node to finish syncing with the cluster in
    seconds
  default: 60
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
consul.require_ssl:
  description: enable ssl for all communication with consul
  default: true
consul.server_cert:
  description: PEM-encoded server certificate
  default: null
consul.server_key:
  description: PEM-encoded server key
  default: null
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
dea_next.crash_lifetime_secs:
  description: Crashed app lifetime in seconds
  default: 3600
dea_next.default_health_check_timeout:
  description: Default timeout for application to start
  default: 60
dea_next.deny_networks:
  description: ""
  default: null
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
dea_next.rlimit_core:
  description: Maximum size of core file in bytes. 0 represents no core dump files
    can be created, and -1 represents no size limits.
  default: 0
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
  description: ""
  default: Cloud Foundry sponsored by Pivotal
disk_quota_enabled:
  description: disk quota must be disabled to use warden-inside-warden with the warden
    cpi
  default: true
domain:
  description: The domain name for this CloudFoundry deploy
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
  description: Port for incoming messages in the dropsonde format
  default: 3457
doppler.enable_tls_transport:
  description: Enable TLS listener on doppler so that it can receive dropsonde envelopes
    over TLS transport. If enabled, Cert and Key files must be specified.
  default: false
doppler.enabled:
  description: Whether to expose the doppler_logging_endpoint listed at /v2/info
  default: true
doppler.incoming_port:
  description: Port for incoming log messages in the legacy format
  default: 3456
doppler.maxRetainedLogMessages:
  description: number of log messages to retain per application
  default: 100
doppler.message_drain_buffer_size:
  description: Size of the internal buffer used by doppler to store messages. If the
    buffer gets full doppler will drop the messages.
  default: 100
doppler.outgoing_port:
  description: Port for outgoing log messages
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
doppler.tls_server.cert:
  description: TLS server certificate
  default: ""
doppler.tls_server.key:
  description: TLS server key
  default: ""
doppler.tls_server.port:
  description: Port for incoming messages in the dropsonde format over tls listener
  default: 3458
doppler.uaa_client_id:
  description: Doppler's client id to connect to UAA
  default: doppler
doppler.unmarshaller_count:
  description: Number of parallel unmarshallers to run within Doppler
  default: 5
doppler.use_ssl:
  description: Whether to use ssl for the doppler_logging_endpoint listed at /v2/info
  default: true
doppler.zone:
  description: Zone of the doppler server
  default: null
doppler_endpoint.shared_secret:
  description: Shared secret used to verify cryptographically signed dropsonde messages
  default: null
dropsonde.enabled:
  description: Enable the dropsonde emitter library
  default: false
env.http_proxy:
  description: The http_proxy accross the VMs
  default: null
env.https_proxy:
  description: The https_proxy accross the VMs
  default: null
env.no_proxy:
  description: Set No_Proxy accross the VMs
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
etcd.election_timeout_in_milliseconds:
  description: Time without recieving a heartbeat before peer should attempt to become
    leader in milliseconds. See https://coreos.com/docs/cluster-management/debugging/etcd-tuning
  default: 1000
etcd.heartbeat_interval_in_milliseconds:
  description: Interval between heartbeats in milliseconds. See https://coreos.com/docs/cluster-management/debugging/etcd-tuning
  default: 50
etcd.log_sync_timeout_in_seconds:
  description: Time to wait for a joining node to finish syncing logs with the existing
    cluster in seconds
  default: 30
etcd.machines:
  description: Addresses of etcd machines
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
etcd_metrics_server.etcd.machine:
  description: address of ETCD server to instrument
  default: 127.0.0.1
etcd_metrics_server.etcd.port:
  description: port of ETCD server to instrument
  default: 4001
etcd_metrics_server.nats.machines:
  description: array of NATS addresses
  default: null
etcd_metrics_server.nats.password:
  description: NATS server password
  default: null
etcd_metrics_server.nats.port:
  description: NATS server port
  default: 4222
etcd_metrics_server.nats.username:
  description: NATS server username
  default: null
etcd_metrics_server.status.password:
  description: basic auth password for metrics server (leave empty for generated)
  default: ""
etcd_metrics_server.status.port:
  description: listening port for metrics server
  default: 5678
etcd_metrics_server.status.username:
  description: basic auth username for metrics server (leave empty for generated)
  default: ""
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
hm9000.desired_state_batch_size:
  description: The batch size when fetching desired state information from the CC.
  default: 5000
hm9000.fetcher_network_timeout_in_seconds:
  description: Each API call to the CC must succeed within this timeout.
  default: 30
hm9000.sender_message_limit:
  description: The maximum number of messages the sender should send per invocation.
  default: 60
hm9000.url:
  description: ""
  default: null
logger_endpoint.port:
  description: Port for logger endpoint listed at /v2/info
  default: 443
logger_endpoint.use_ssl:
  description: Whether to use ssl for logger endpoint listed at /v2/info
  default: true
loggregator.doppler_port:
  description: Port for outgoing doppler messages
  default: 8081
loggregator.dropsonde_incoming_port:
  description: Port where loggregator listens for dropsonde log messages
  default: 3457
loggregator.etcd.machines:
  description: IPs pointing to the ETCD cluster
  default: null
loggregator.etcd.maxconcurrentrequests:
  description: Number of concurrent requests to ETCD
  default: 10
loggregator.outgoing_dropsonde_port:
  description: Port for outgoing dropsonde messages
  default: 8081
loggregator.tls.ca:
  description: CA root required for key/cert verification
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
login.analytics.code:
  description: Analytics code
  default: null
login.analytics.domain:
  description: Analytics domain
  default: null
login.asset_base_url:
  description: Base url for static assets, allows custom styling of the login server.
  default: null
login.brand:
  description: The branding style to use with the web interface, account confirmation,
    and password reset emails.
  default: oss
login.catalina_opts:
  description: ""
  default: null
login.enabled:
  description: whether use login as the authorization endpoint or not
  default: true
login.entity_id:
  description: 'Deprecated: Use login.saml.entityid'
  default: null
login.invitations_enabled:
  description: Allows users to send invitations to email addresses outside the system
    and invite them to create an account. Disabled by default.
  default: null
login.ldap.localPasswordCompare:
  description: See uaa.ldap.localPasswordCompare - login.ldap prefix is used for backwards
    compatibility to enable ldap from login config
  default: "true"
login.ldap.passwordAttributeName:
  description: See uaa.ldap.passwordAttributeName - login.ldap prefix is used for
    backwards compatibility to enable ldap from login config
  default: userPassword
login.ldap.passwordEncoder:
  description: See uaa.ldap.passwordEncoder - login.ldap prefix is used for backwards
    compatibility to enable ldap from login config
  default: org.cloudfoundry.identity.uaa.login.ldap.DynamicPasswordComparator
login.ldap.profile_type:
  description: See uaa.ldap.profile_type - login.ldap prefix is used for backwards
    compatibility to enable ldap from login config
  default: null
login.ldap.searchBase:
  description: See uaa.ldap.searchBase - login.ldap prefix is used for backwards compatibility
    to enable ldap from login config
  default: ""
login.ldap.searchFilter:
  description: See uaa.ldap.searchFilter - login.ldap prefix is used for backwards
    compatibility to enable ldap from login config
  default: cn={0}
login.ldap.sslCertificate:
  description: See uaa.ldap.sslCertificate - login.ldap prefix is used for backwards
    compatibility to enable ldap from login config
  default: null
login.ldap.sslCertificateAlias:
  description: See uaa.ldap.sslCertificateAlias - login.ldap prefix is used for backwards
    compatibility to enable ldap from login config
  default: null
login.ldap.url:
  description: See uaa.ldap.url - login.ldap prefix is used for backwards compatibility
    to enable ldap from login config
  default: null
login.ldap.userDN:
  description: See uaa.ldap.userDN - login.ldap prefix is used for backwards compatibility
    to enable ldap from login config
  default: null
login.ldap.userDNPattern:
  description: See uaa.ldap.userDNPattern - login.ldap prefix is used for backwards
    compatibility to enable ldap from login config
  default: null
login.ldap.userPassword:
  description: See uaa.ldap.userPassword - login.ldap prefix is used for backwards
    compatibility to enable ldap from login config
  default: null
login.links:
  description: A hash of home/passwd/signup URLS (see commented examples below)
  default: null
login.links.passwd:
  description: URL for requesting password reset
  default: null
login.links.signup:
  description: URL for requesting to signup/register for an account
  default: null
login.logout.redirect.parameter.disable:
  description: When set to false, this allows an operator to leverage an open redirect
    on the UAA (/logout.do?redirect=google.com). Default value is true. No open redirect
    enabled
  default: null
login.logout.redirect.parameter.whitelist:
  description: A list of URLs. When this list is non null, including empty, and disable=false,
    logout redirects are allowed, but limited to the whitelist URLs. If a redirect
    parameter value is not white listed, redirect will be to the default URL.
  default: null
login.logout.redirect.url:
  description: The Location of the redirect header following a logout of the the UAA
    (/logout.do). Default value is back to login page (/login)
  default: null
login.messages:
  description: |
    A nested or flat hash of messages that the login server uses to display UI message
    This will be flattened into a java.util.Properties file. The example below will lead
    to four properties, where the key is the concatenated value delimited by dot, for example scope.tokens.read=message
    Nested example:
    messages:
      scope:
        tokens:
          read: View details of your approvals you have granted to this and other applications
          write: Cancel the approvals like this one that you have granted to this and other applications
        cloud_controller:
          read: View details of your applications and services
          write: Push applications to your account and create and bind services
    Flat example:
    messages:
      scope.tokens.read: View details of your approvals you have granted to this and other applications
      scope.tokens.write: Cancel the approvals like this one that you have granted to this and other applications
      scope.cloud_controller.read: View details of your applications and services
      scope.cloud_controller.write: Push applications to your account and create and bind services
  default: null
login.notifications.url:
  description: The url for the notifications service (configure to use Notifications
    Service instead of SMTP server)
  default: null
login.port:
  description: ""
  default: 8080
login.prompt.password.text:
  description: The text used to prompt for a password during login
  default: Password
login.prompt.username.text:
  description: The text used to prompt for a username during login
  default: Email
login.protocol:
  description: Scheme to use for HTTP communication (http/https)
  default: https
login.saml.assertion_consumer_index:
  description: 'Deprecated: Use login.saml.providers list objects'
  default: 1
login.saml.entity_base_url:
  description: 'The URL for which SAML identity providers will post assertions to.
    If set it overrides the default of login.<domain>. This URL should NOT have the
    schema (http:// or https:// prefix in it) instead just the hostname. The schema
    is derived by login.protocol property. The default value is #{protocol}://login.#{properties.domain}'
  default: null
login.saml.entityid:
  description: The ID to represent this server
  default: null
login.saml.idp_metadata_file:
  description: 'Deprecated: Use login.saml.providers list objects'
  default: null
login.saml.idpEntityAlias:
  description: 'Deprecated: Use login.saml.providers list objects'
  default: null
login.saml.idpMetadataURL:
  description: 'Deprecated: Use login.saml.providers list objects'
  default: null
login.saml.keystore_key:
  description: Key name of the SAML login server keystore.
  default: selfsigned
login.saml.keystore_name:
  description: Name of the SAML login server keystore.
  default: samlKeystore.jks
login.saml.keystore_password:
  description: Key password to the SAML login server keystore.
  default: password
login.saml.metadataTrustCheck:
  description: 'Deprecated: Use login.saml.providers list objects'
  default: true
login.saml.nameidFormat:
  description: 'Deprecated: Use login.saml.providers list objects'
  default: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
login.saml.providers:
  description: Contains a hash of SAML Identity Providers, the key is the IDP Alias,
    followed by key/value pairs for idpMetadata, nameID, assertionConsumerIndex, metadataTrustCheck,
    showSamlLoginLink, linkText, iconUrl
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
  description: Set to true, if you wish that the UAA signs its SAML metadata
  default: true
login.saml.signRequest:
  description: Set to true, if you wish the that the UAA signs all its SAML auth requests
  default: true
login.saml.socket.connectionManagerTimeout:
  description: Timeout in milliseconds for connection pooling for SAML metadata HTTP
    requests
  default: null
login.saml.socket.soTimeout:
  description: Read timeout in milliseconds for SAML metadata HTTP requests
  default: null
login.self_service_links_enabled:
  description: Enable self-service account creation and password resets links.
  default: null
login.signups_enabled:
  description: Enable account creation flow in the login server. Enabled by default.
  default: null
login.smtp:
  description: SMTP server configuration, for password reset emails etc.
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
login.smtp.user:
  description: SMTP server username
  default: null
login.spring_profiles:
  description: See uaa.spring_profiles - login.spring_profiles is used for backwards
    compatibility to enable ldap from login config
  default: null
login.tiles:
  description: A list of links to other services to show on the landing page after
    logging in and/or signing up, depending on whether login-link and/or signup-link
    is specified.
  default: null
login.uaa_base:
  description: Location of the UAA.
  default: null
login.uaa_certificate:
  description: Certificate to import if the UAA is using self-signed certificates
  default: null
login.url:
  description: ""
  default: null
metron_agent.debug:
  description: boolean value to turn on verbose mode
  default: false
metron_agent.deployment:
  description: Name of deployment (added as tag on all outgoing metrics)
  default: null
metron_agent.dropsonde_incoming_port:
  description: Incoming port for dropsonde log messages
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
  description: Preferred protocol to droppler (udp|tls)
  default: udp
metron_agent.tls_client.cert:
  description: TLS client certificate
  default: ""
metron_agent.tls_client.key:
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
  description: The port used to emit legacy messages to the Metron agent.
  default: 3456
metron_endpoint.shared_secret:
  description: Shared secret used to verify cryptographically signed dropsonde messages
  default: null
name:
  description: ""
  default: vcap
nats.authorization_timeout:
  description: After accepting a connection, wait up to this many seconds for credentials.
  default: 15
nats.debug:
  description: Enable debug logging output.
  default: false
nats.machines:
  description: IP of each NATS cluster member.
  default: null
nats.monitor_port:
  description: Port for varz and connz monitoring. 0 means disabled.
  default: 0
nats.password:
  description: Password for NATS login
  default: null
nats.port:
  description: TCP port of NATS server
  default: null
nats.prof_port:
  description: Port for pprof. 0 means disabled.
  default: 0
nats.trace:
  description: Enable trace logging output.
  default: false
nats.user:
  description: User name for NATS login
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
  description: Location to mount the nfs share
  default: /var/vcap/nfs
request_timeout_in_seconds:
  description: Server and client timeouts in seconds
  default: 900
route_registrar.routes:
  description: |
    * Array of hashes determining which routes will be registered.
    * Each hash should have 'port', 'uris', and 'name' keys.
    * Additionally, the 'tags' key is optional.
    * 'uris' is an array of URIs to register for the 'port'.
    * 'tags' are included in metrics that gorouter emits to support filtering.
  default: null
route_registrar.update_frequency_in_seconds:
  description: The delay in seconds between routing updates
  default: 20
router.acceptance_tests.bbs.api_location:
  description: Diego BBS Server endpoint url
  default: https://bbs.service.cf.internal:8889
router.acceptance_tests.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
router.acceptance_tests.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
router.acceptance_tests.bbs.client_key:
  description: PEM-encoded client key
  default: null
router.acceptance_tests.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
router.acceptance_tests.elb_address:
  description: (Optional) ELB Address to check connectivity through load balancer
  default: ""
router.acceptance_tests.gorouter_secret:
  description: Password for UAA client for the gorouter.
  default: null
router.acceptance_tests.nodes:
  description: The number of parallel test executors to spawn. The larger the number
    the higher the stress on the system.
  default: 4
router.acceptance_tests.router_api_addresses:
  description: Router API IP Address
  default:
  - 10.244.8.2
router.acceptance_tests.router_api_port:
  description: Router API IP Port
  default: 9999
router.acceptance_tests.uaa_port:
  description: Port on which UAA is running.
  default: "8080"
router.acceptance_tests.verbose:
  description: Whether to pass the -v flag to router acceptance tests
  default: false
router.cipher_suites:
  description: An ordered list of supported SSL cipher suites containing golang tls
    constants separated by colons The cipher suite will be chosen according to this
    order during SSL handshake For example, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  default: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA
router.debug_addr:
  description: Address at which to serve debug info
  default: 0.0.0.0:17001
router.enable_routing_api:
  description: Enable the GoRouter to receive routes from the Routing API
  default: true
router.enable_ssl:
  description: Enable ssl termination on the router
  default: false
router.extra_headers_to_log:
  description: A list of headers that log events will be annotated with
  default: []
router.haproxy.health_check_port:
  description: Port that is used to check the health of HA-proxy
  default: 80
router.haproxy.request_timeout_in_seconds:
  description: Server and client timeouts in seconds
  default: 300
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
  description: Listening port for Router
  default: 80
router.requested_route_registration_interval_in_seconds:
  description: Interval at which the router requests routes to be registered.
  default: 20
router.route_service_timeout:
  description: Expiry time of a route service signature in seconds
  default: 60
router.route_services_secret:
  description: Support for route services is disabled when no value is configured.
  default: ""
router.route_services_secret_decrypt_only:
  description: To rotate keys, add your new key here and deploy. Then swap this key
    with the value of route_services_secret and deploy again.
  default: ""
router.router_configurer.debug_addr:
  description: Address at which to serve debug info
  default: 0.0.0.0:17014
router.router_configurer.gorouter_secret:
  description: Password for UAA client for the gorouter.
  default: null
router.router_configurer.log_level:
  description: Log level
  default: info
router.router_configurer.routing_api_auth_disabled:
  description: auth disabled setting of routing api
  default: false
router.router_configurer.routing_api_port:
  description: Port of routing api
  default: "3000"
router.router_configurer.tcp_config_file:
  description: Config file of underlying tcp proxy
  default: /var/vcap/jobs/haproxy/config/haproxy.conf
router.router_configurer.tcp_config_file_template:
  description: Base Config file of underlying tcp proxy
  default: /var/vcap/jobs/haproxy/config/haproxy.conf.template
router.router_configurer.uaa_port:
  description: Port on which UAA is running.
  default: "8080"
router.secure_cookies:
  description: Set secure flag on http cookies
  default: false
router.servers.z1:
  description: Array of the router IPs acting as the first group of HTTP/TCP backends
  default: []
router.servers.z2:
  description: Array of the router IPs acting as the second group of HTTP/TCP backends
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
router.tcp_emitter.bbs.api_location:
  description: Diego BBS Server endpoint url
  default: http://bbs.service.cf.internal:8889
router.tcp_emitter.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
router.tcp_emitter.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
router.tcp_emitter.bbs.client_key:
  description: PEM-encoded client key
  default: null
router.tcp_emitter.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
router.tcp_emitter.consul_cluster:
  description: comma-separated list of consul server URLs (scheme://ip:port)
  default: http://127.0.0.1:8500
router.tcp_emitter.debug_addr:
  description: Address at which to serve debug info
  default: 0.0.0.0:17016
router.tcp_emitter.gorouter_secret:
  description: Password for UAA client for the gorouter.
  default: null
router.tcp_emitter.lock_retry_interval:
  description: interval to wait before retrying a failed lock acquisition
  default: 5s
router.tcp_emitter.lock_ttl:
  description: TTL for service lock
  default: 10s
router.tcp_emitter.log_level:
  description: Log level
  default: info
router.tcp_emitter.routing_api_auth_disabled:
  description: auth disabled setting of routing api
  default: false
router.tcp_emitter.routing_api_port:
  description: Port of routing api
  default: "3000"
router.tcp_emitter.session_name:
  description: consul session name
  default: tcp-emitter
router.tcp_emitter.uaa_port:
  description: Port on which UAA is running.
  default: "8080"
router.trace_key:
  description: If the X-Vcap-Trace request header is set and has this value, trace
    headers are added to the response.
  default: 22
routing-api.auth_disabled:
  description: Disables UAA authentication
  default: false
routing-api.debug_address:
  description: Address at which to serve debug info
  default: 0.0.0.0:17002
routing-api.max_concurrent_etcd_requests:
  description: Maximum number of concurrent ETCD requests
  default: 25
routing-api.max_ttl:
  description: The maximum ttl
  default: 60
routing-api.metrics_reporting_interval:
  description: 'String representing interval for reporting metrics. Units: ms, s,
    m h'
  default: 30s
routing-api.port:
  description: The port to run the routing api on
  default: 3000
routing-api.statsd_client_flush_interval:
  description: Buffered statsd client flush interval
  default: 300ms
routing-api.statsd_endpoint:
  description: The endpoint for the statsd server, defaults to the local metron agent
  default: localhost:8125
smoke_tests.api:
  description: The Elastic Runtime API endpoint URL
  default: null
smoke_tests.apps_domain:
  description: The Elastic Runtime Application Domain
  default: null
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
  description: when connecting over https, ignore bad ssl certificates
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
  description: ""
  default: http://support.cloudfoundry.com
syslog_daemon_config.address:
  description: IP address for syslog aggregator
  default: null
syslog_daemon_config.custom_rule:
  description: Custom rule for syslog forward daemon
  default: ""
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
  description: boolean value to turn on verbose logging for syslog_drain_binder
  default: false
syslog_drain_binder.drain_url_ttl_seconds:
  description: Time to live for drain urls in seconds
  default: 60
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
  description: The User Org that owns the system_domain, required if system_domain
    is defined
  default: ""
traffic_controller.debug:
  description: boolean value to turn on verbose logging for loggregator system (dea
    agent & loggregator server)
  default: false
traffic_controller.outgoing_port:
  description: Port on which the traffic controller listens to for requests
  default: 8080
traffic_controller.zone:
  description: Zone of the loggregator_trafficcontroller
  default: null
uaa.admin.client_secret:
  description: Secret of the admin client - a client named admin with uaa.admin as
    an authority
  default: null
uaa.authentication.policy.countFailuresWithinSeconds:
  description: Number of seconds in which lockoutAfterFailures failures must occur
    in order for account to be locked
  default: null
uaa.authentication.policy.lockoutAfterFailures:
  description: Number of allowed failures before account is locked
  default: null
uaa.authentication.policy.lockoutPeriodSeconds:
  description: Number of seconds to lock out an account when lockoutAfterFailures
    failures is exceeded
  default: null
uaa.catalina_opts:
  description: ""
  default: -Xmx768m -XX:MaxPermSize=256m
uaa.cc.client_secret:
  description: ""
  default: null
uaa.cc.token_secret:
  description: ""
  default: null
uaa.client.autoapprove:
  description: ""
  default: null
uaa.clients:
  description: ""
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
  description: Doppler's client secret to connect to UAA
  default: null
uaa.clients.gorouter.secret:
  description: Password for UAA client for the gorouter.
  default: null
uaa.clients.login.secret:
  description: Login client secret - overrides uaa.login.client_secret
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
uaa.database.remove_abandoned:
  description: True if connections that are left open longer then abandoned_timeout
    seconds during a session(time between borrow and return from pool)  should be
    forcibly closed
  default: false
uaa.disableInternalAuth:
  description: Disables internal user authentication
  default: false
uaa.disableInternalUserManagement:
  description: Disables UI and API for internal user management
  default: false
uaa.dump_requests:
  description: ""
  default: null
uaa.id_token.disable:
  description: 'Deprecated: When set to true, requests to /oauth/authorize will ignore
    the response_type=id_token parameter'
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
uaa.jwt.policy.global.accessTokenValiditySeconds:
  description: The global access token validity for all zones if nothing is configured
    on the client
  default: 43200
uaa.jwt.policy.global.refreshTokenValiditySeconds:
  description: The global refresh token validity for all zones if nothing is configured
    on the client
  default: 2592000
uaa.jwt.policy.keys:
  description: Map of key ids to key pairs (signing and verification keys)
  default: null
uaa.jwt.policy.refreshTokenValiditySeconds:
  description: The refresh token validity for the default zone if nothing is configured
    on the client. Will override global validity policies for the default zone only.
  default: 2592000
uaa.jwt.signing_key:
  description: ""
  default: null
uaa.jwt.verification_key:
  description: The verification key for UAA
  default: null
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
uaa.ldap.groups.autoAdd:
  description: Set to true when profile_type=groups_as_scopes to auto create scopes
    for a user. Ignored for other profiles.
  default: "true"
uaa.ldap.groups.groupRoleAttribute:
  description: Used with groups-as-scopes, defines the attribute that holds the scope
    name(s).
  default: null
uaa.ldap.groups.groupSearchFilter:
  description: Search query filter to find groups a user belongs to, or for a nested
    search, groups that a group belongs to
  default: member={0}
uaa.ldap.groups.maxSearchDepth:
  description: Set to number of levels a nested group search should go. Set to 1 to
    disable nested groups (default)
  default: "1"
uaa.ldap.groups.profile_type:
  description: What type of group integration should be used. Values are no-groups,
    groups-as-scopes and groups-map-to-scopes
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
  description: The file to be used for configuring the LDAP authentication. options
    are simple-bind, search-and-bind and search-and-compare
  default: search-and-bind
uaa.ldap.searchBase:
  description: Used with search-and-bind and search-and-compare. Define a base where
    the search starts at.
  default: ""
uaa.ldap.searchFilter:
  description: Used with search-and-bind and search-and-compare. Search filter used.
    Takes one parameter, user ID defined as {0}
  default: cn={0}
uaa.ldap.sslCertificate:
  description: Used with ldaps:// URLs. The certificate, if self signed, to be trusted
    by this connection.
  default: null
uaa.ldap.sslCertificateAlias:
  description: Used with ldaps:// URLs. The certificate alias, to be trusted by this
    connection and stored in the keystore.
  default: null
uaa.ldap.url:
  description: The URL to the ldap server, must start with ldap:// or ldaps://
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
  description: The delimiter character in between user DN patterns for simple bind
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
  description: Sets the time format for log messages to be rfc3339 compatible.
  default: false
uaa.login.client_secret:
  description: Deprecated. Default login client secret if no login client is defined
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
uaa.no_ssl:
  description: Do not use SSL to connect to UAA (used in case uaa.url is not set)
  default: false
uaa.password.policy.expirePasswordInMonths:
  description: Number of months after which current password expires
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
    These will be added to the proxy_ips_regex as exact matches. When using spiff,
    these will be router_z1 and router_z2 static IPs from cf-jobs.yml
  default: []
uaa.proxy_ips_regex:
  description: |
    A pipe delimited set of regular expressions of IP addresses that are considered reverse proxies.
    When a request from these IP addresses come in, the x-forwarded-for and x-forwarded-proto headers will be respected.
    If the uaa.restricted_ips_regex is set, it will be appended to this list for backwards compatibility purposes
    If spiff has been used and includes templates/cf-jobs.yml to generate the manifest. This list will automatically
    contain the Router IP addresses
  default: 10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.1[6-9]{1}\.\d{1,3}\.\d{1,3}|172\.2[0-9]{1}\.\d{1,3}\.\d{1,3}|172\.3[0-1]{1}\.\d{1,3}\.\d{1,3}
uaa.require_https:
  description: ""
  default: null
uaa.restricted_ips_regex:
  description: '[Not Currently Used] A pipe delimited set of regular expressions of
    IP addresses that can reach the listening HTTP port of the server.'
  default: null
uaa.scim.external_groups:
  description: A list of external group mappings. Pipe delimited. A value may look
    as '- internal.read|cn=developers,ou=scopes,dc=test,dc=com'
  default: null
uaa.scim.groups:
  description: Comma separated list of groups that should be added to the UAA db,
    but not assigned to a user by default.
  default: null
uaa.scim.user:
  description: ""
  default: null
uaa.scim.user.override:
  description: ""
  default: true
uaa.scim.userids_enabled:
  description: ""
  default: true
uaa.scim.users:
  description: ""
  default: null
uaa.spring_profiles:
  description: Deprecated. Use 'uaa.ldap.enabled'. Sets the Spring profiles on the
    UAA web application. This gets combined with the 'uaadb.db_scheme' property if
    and only if the value is exactly 'ldap' in order to setup the database, for example
    'ldap,mysql'. If spring_profiles contains more than just 'ldap' it will be used
    to overwrite spring_profiles and db_scheme ignored. See uaa.yml.erb.
  default: null
uaa.url:
  description: URL of UAA
  default: null
uaa.user.authorities:
  description: Contains a list of the default authorities/scopes assigned to a user.
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
uaa.zones.internal.hostnames:
  description: |
    A list of hostnames that are routed to the UAA, specifically the default zone in the UAA. The UAA will reject any Host headers that it doesn't recognize.
    By default the UAA recognizes
    uaa.<domain> - the default UAA route
    login.<domain> - the login-server route that the UAA now also serves.
    localhost - in order to accept health checks
    Any hostnames added as a list are additive to the default hostnames allowed.
    Example
    uaa:
      zones:
        internal:
          hostnames:
            - hostname1
            - hostname2.localhost
            - hostname3.example.com
  default:
  - uaa.service.cf.internal
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
  description: ""
  default: "2"

