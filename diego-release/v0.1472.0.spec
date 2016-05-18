benchmark-bbs.active_key_label:
  description: the active key for encryption
  default: null
benchmark-bbs.aws_access_key_id:
  description: the aws access key for uploading metrics to s3
  default: ""
benchmark-bbs.aws_bucket_name:
  description: the S3 bucket to upload metrics to
  default: ""
benchmark-bbs.aws_region:
  description: the aws region where the S3 bucket lives
  default: ""
benchmark-bbs.aws_secret_access_key:
  description: the aws secret key for uploading metrics to s3
  default: ""
benchmark-bbs.bbs.api_location:
  description: the address of the BBS
  default: bbs.service.cf.internal:8889
benchmark-bbs.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
benchmark-bbs.bbs.client_key:
  description: PEM-encoded client key
  default: null
benchmark-bbs.bbs.etcd.max_idle_conns_per_host:
  description: maximum number of etcd client idle http connections
  default: null
benchmark-bbs.bbs.require_ssl:
  description: enable ssl for all communication with the bbs (false unsupported)
  default: true
benchmark-bbs.client_timeout:
  description: the http timeout for bbs client requests
  default: null
benchmark-bbs.datadog_api_key:
  description: the api key for emmitting datadog metrics
  default: ""
benchmark-bbs.datadog_app_key:
  description: the application key for datadog metrics
  default: ""
benchmark-bbs.datadog_metric_prefix:
  description: the datadog metric prefix
  default: ""
benchmark-bbs.desired_lrps:
  description: the number of single instance desired lrps to generate and fetch
  default: null
benchmark-bbs.encryption_keys:
  description: the key(s) to use for encryption at rest
  default: []
benchmark-bbs.etcd.ca_cert:
  description: PEM-encoded root CA certificate
  default: null
benchmark-bbs.etcd.client_cert:
  description: PEM-encoded client certificate
  default: null
benchmark-bbs.etcd.client_key:
  description: PEM-encoded client key
  default: null
benchmark-bbs.etcd.client_session_cache_size:
  description: capacity of the etcd client tls client cache
  default: null
benchmark-bbs.etcd.machines:
  description: Addresses pointing to the ETCD cluster
  default: null
benchmark-bbs.etcd.require_ssl:
  description: boolean to configure ssl connections with the etcd cluster
  default: true
benchmark-bbs.ginkgo_nodes:
  description: number of parallel ginkgo nodes to run
  default: 4
benchmark-bbs.log_file:
  description: file name for benchmark log output in the BOSH log dir
  default: null
benchmark-bbs.log_level:
  description: 'log level: debug, info, error or fatal'
  default: null
benchmark-bbs.num_populate_workers:
  description: the number of workers generating desired LRPs during setup
  default: null
benchmark-bbs.num_reps:
  description: the number of rep processes to simulate in test
  default: null
benchmark-bbs.num_trials:
  description: the number of trials of each benchmark to average across
  default: null
benchmark-bbs.percent_writes:
  description: percentage of actual LRPs to write on each rep bulk loop
  default: 5
benchmark-bbs.sql.db_connection_string:
  description: 'EXPERIMENTAL: connection string to use for SQL backend [username:password@tcp(1.1.1.1:1234)/database]'
  default: null
diego.auctioneer.bbs.api_location:
  description: Address to the BBS Server
  default: bbs.service.cf.internal:8889
diego.auctioneer.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
diego.auctioneer.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
diego.auctioneer.bbs.client_key:
  description: PEM-encoded client key
  default: null
diego.auctioneer.bbs.client_session_cache_size:
  description: capacity of the tls client cache
  default: null
diego.auctioneer.bbs.max_idle_conns_per_host:
  description: maximum number of idle http connections
  default: null
diego.auctioneer.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
diego.auctioneer.cell_state_timeout:
  description: Timeout applied to HTTP requests to the Cell State endpoint.
  default: 1s
diego.auctioneer.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17001
diego.auctioneer.dropsonde_port:
  description: local metron agent's port
  default: 3457
diego.auctioneer.listen_addr:
  description: address where auctioneer listens for LRP and task start auction requests
  default: 0.0.0.0:9016
diego.auctioneer.log_level:
  description: Log level
  default: info
diego.auctioneer.starting_container_weight:
  description: Factor to bias against cells with starting containers (0.0 - 1.0)
  default: 0.25
diego.bbs.active_key_label:
  description: Label of the encryption key to be used when writing to the database
  default: null
diego.bbs.advertisement_base_hostname:
  description: Suffix for the BBS advertised hostname
  default: bbs.service.cf.internal
diego.bbs.auctioneer.api_url:
  description: Address of the auctioneer API
  default: http://auctioneer.service.cf.internal:9016
diego.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
diego.bbs.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17017
diego.bbs.desired_lrp_creation_timeout:
  description: expected maximum time to create all components of a desired LRP
  default: null
diego.bbs.dropsonde_port:
  description: local metron agent's port
  default: 3457
diego.bbs.encryption_keys:
  description: List of encryption keys to be used
  default: []
diego.bbs.etcd.ca_cert:
  description: PEM-encoded CA certificate
  default: null
diego.bbs.etcd.client_cert:
  description: PEM-encoded client certificate
  default: null
diego.bbs.etcd.client_key:
  description: PEM-encoded client key
  default: null
diego.bbs.etcd.client_session_cache_size:
  description: capacity of the tls client cache
  default: null
diego.bbs.etcd.machines:
  description: Addresses pointing to the ETCD cluster
  default:
  - etcd.service.cf.internal
diego.bbs.etcd.max_idle_conns_per_host:
  description: maximum number of idle http connections
  default: null
diego.bbs.etcd.require_ssl:
  description: enable ssl for all communication with etcd
  default: true
diego.bbs.listen_addr:
  description: address at which to serve API requests
  default: 0.0.0.0:8889
diego.bbs.log_level:
  description: Log level
  default: info
diego.bbs.require_ssl:
  description: require ssl for all communication the bbs
  default: true
diego.bbs.server_cert:
  description: PEM-encoded client certificate
  default: null
diego.bbs.server_key:
  description: PEM-encoded client key
  default: null
diego.bbs.sql.ca_cert:
  description: The ca cert bundle to verify SQL connections against
  default: ""
diego.bbs.sql.db_connection_string:
  description: 'EXPERIMENTAL: connection string to use for SQL backend [username:password@tcp(1.1.1.1:1234)/database]'
  default: null
diego.bbs.sql.max_open_connections:
  description: Maximum number of open connections to the SQL database
  default: null
diego.canary.api:
  description: The Elastic Runtime API endpoint URL
  default: null
diego.canary.app_domain:
  description: The domain to use for the canary app
  default: null
diego.canary.app_name:
  description: App name for the canary app
  default: null
diego.canary.cf_stack:
  description: Stack for the canary app
  default: cflinuxfs2
diego.canary.datadog_api_key:
  description: Datadog API key for the canary app
  default: null
diego.canary.deployment_name:
  description: Deployment name for the canary app
  default: null
diego.canary.instance_count:
  description: Number of instances of the canary app
  default: null
diego.canary.org:
  description: The Elastic Runtime organization name to use for the canary app
  default: null
diego.canary.password:
  description: The Elastic Runtime API user's password
  default: null
diego.canary.space:
  description: The Elastic Runtime space name to use for the canary app
  default: null
diego.canary.user:
  description: The Elastic Runtime API user
  default: null
diego.converger.bbs.api_location:
  description: Address to the BBS Server
  default: bbs.service.cf.internal:8889
diego.converger.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
diego.converger.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
diego.converger.bbs.client_key:
  description: PEM-encoded client key
  default: null
diego.converger.bbs.client_session_cache_size:
  description: capacity of the tls client cache
  default: null
diego.converger.bbs.max_idle_conns_per_host:
  description: maximum number of idle http connections
  default: null
diego.converger.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
diego.converger.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17002
diego.converger.dropsonde_port:
  description: local metron agent's port
  default: 3457
diego.converger.expire_completed_task_duration_in_seconds:
  description: completed, unresolved tasks are deleted after this duration in seconds
  default: 120
diego.converger.expire_pending_task_duration_in_seconds:
  description: unclaimed tasks are marked as failed, after this duration in seconds
  default: 1800
diego.converger.kick_task_duration_in_seconds:
  description: the interval, in seconds, between kicks to tasks in seconds
  default: 30
diego.converger.log_level:
  description: Log level
  default: info
diego.converger.repeat_interval_in_seconds:
  description: the interval between runs of the converge process
  default: 30
diego.executor.ca_certs_for_downloads:
  description: Concatenation of trusted CA certificates to be used when downloading
    assets.
  default: null
diego.executor.cache_path:
  description: path to the executor's cache
  default: /var/vcap/data/executor_cache
diego.executor.container_inode_limit:
  description: the inode limit enforced on each garden container.
  default: 200000
diego.executor.container_max_cpu_shares:
  description: the maximum number of cpu shares for a container.
  default: 1024
diego.executor.create_work_pool_size:
  description: Maximum number of concurrent create container operations.
  default: 32
diego.executor.delete_work_pool_size:
  description: Maximum number of concurrent delete container operations.
  default: 32
diego.executor.disk_capacity_mb:
  description: the container disk capacity the executor should manage.  this should
    not be greater than the actual disk quota on the VM
  default: auto
diego.executor.export_network_env_vars:
  description: Export network environment variables into container (e.g. CF_INSTANCE_IP,
    CF_INSTANCE_PORT).
  default: true
diego.executor.garden.address:
  description: Garden server listening address.
  default: /var/vcap/data/garden/garden.sock
diego.executor.garden.network:
  description: Network type for the garden server connection (tcp or unix).
  default: unix
diego.executor.garden_healthcheck.command_retry_pause:
  description: Time to wait between retrying garden commands
  default: 5s
diego.executor.garden_healthcheck.interval:
  description: Frequency for healtchecking garden
  default: 10m
diego.executor.garden_healthcheck.process.args:
  description: List of command line args to pass to the garden health check process
  default: -c, ls > /tmp/test
diego.executor.garden_healthcheck.process.dir:
  description: Directory to run the healthcheck process from
  default: null
diego.executor.garden_healthcheck.process.env:
  description: Environment variables to use when running the garden health check
  default: null
diego.executor.garden_healthcheck.process.path:
  description: Path of the command to run to perform a container healthcheck
  default: /bin/sh
diego.executor.garden_healthcheck.process.user:
  description: User to use while performing a container healthcheck
  default: vcap
diego.executor.garden_healthcheck.timeout:
  description: Maximum allowed time for garden healthcheck
  default: 10m
diego.executor.healthcheck_work_pool_size:
  description: Maximum number of concurrent health check operations.
  default: 64
diego.executor.healthy_monitoring_interval_in_seconds:
  description: Interval to check healthy containers in seconds.
  default: 30
diego.executor.max_cache_size_in_bytes:
  description: maximum size of the cache in bytes - this should leave a healthy overhead
    for temporary items, etc.
  default: 10000000000
diego.executor.max_concurrent_downloads:
  description: the max concurrent download steps that can be active
  default: 5
diego.executor.memory_capacity_mb:
  description: the memory capacity the executor should manage.  this should not be
    greater than the actual memory on the VM
  default: auto
diego.executor.metrics_work_pool_size:
  description: Maximum number of concurrent get container metrics operations.
  default: 8
diego.executor.post_setup_hook:
  description: 'Experimental: arbitrary command to run after setup action'
  default: null
diego.executor.post_setup_user:
  description: 'Experimental: user to run post setup hook command'
  default: null
diego.executor.read_work_pool_size:
  description: Maximum number of concurrent get container info operations.
  default: 64
diego.executor.unhealthy_monitoring_interval_in_seconds:
  description: Interval to check unhealthy containers in seconds.
  default: 0.5
diego.executor.volman.driver_paths:
  description: 'Experimental: OS style path string containing the directories volman
    will look in for voldriver specs (delimited by : or ; depending on the OS)'
  default: null
diego.file_server.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17005
diego.file_server.dropsonde_port:
  description: local metron agent's port
  default: 3457
diego.file_server.listen_addr:
  description: Address of interface on which to serve files
  default: 0.0.0.0:8080
diego.file_server.log_level:
  description: Log level
  default: info
diego.file_server.static_directory:
  description: Fully-qualified path to the doc root for the file server's static files
  default: /var/vcap/jobs/file_server/packages/
diego.rep.bbs.api_location:
  description: Address to the BBS Server
  default: bbs.service.cf.internal:8889
diego.rep.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
diego.rep.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
diego.rep.bbs.client_key:
  description: PEM-encoded client key
  default: null
diego.rep.bbs.client_session_cache_size:
  description: capacity of the tls client cache
  default: null
diego.rep.bbs.max_idle_conns_per_host:
  description: maximum number of idle http connections
  default: null
diego.rep.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
diego.rep.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17008
diego.rep.dropsonde_port:
  description: local metron agent's port
  default: 3457
diego.rep.evacuation_polling_interval_in_seconds:
  description: The interval to look for completed tasks and LRPs during evacuation
    in seconds
  default: 10
diego.rep.evacuation_timeout_in_seconds:
  description: The time to wait for evacuation to complete in seconds
  default: 600
diego.rep.listen_addr:
  description: address to serve auction and LRP stop requests on
  default: 0.0.0.0:1800
diego.rep.log_level:
  description: Log level
  default: info
diego.rep.polling_interval_in_seconds:
  description: The interval to look for completed tasks and LRPs in seconds
  default: 30
diego.rep.preloaded_rootfses:
  description: Array of name:absolute_path pairs representing root filesystems preloaded
    onto the underlying garden
  default: null
diego.rep.rootfs_providers:
  description: Array of schemes for which the underlying garden can support arbitrary
    root filesystems
  default:
  - docker
diego.rep.trusted_certs:
  description: Concatenation of trusted CA certificates to be made available inside
    the rootfses
  default: null
diego.rep.zone:
  description: The zone associated with the rep
  default: null
diego.route_emitter.bbs.api_location:
  description: Address to the BBS Server
  default: bbs.service.cf.internal:8889
diego.route_emitter.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
diego.route_emitter.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
diego.route_emitter.bbs.client_key:
  description: PEM-encoded client key
  default: null
diego.route_emitter.bbs.client_session_cache_size:
  description: capacity of the tls client cache
  default: null
diego.route_emitter.bbs.max_idle_conns_per_host:
  description: maximum number of idle http connections
  default: null
diego.route_emitter.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
diego.route_emitter.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17009
diego.route_emitter.dropsonde_port:
  description: local metron agent's port
  default: 3457
diego.route_emitter.log_level:
  description: Log level
  default: info
diego.route_emitter.nats.machines:
  description: IP of each NATS cluster member.
  default: null
diego.route_emitter.nats.password:
  description: Password for server authentication.
  default: null
diego.route_emitter.nats.port:
  description: The port for the NATS server to listen on.
  default: 4222
diego.route_emitter.nats.user:
  description: Username for server authentication.
  default: null
diego.route_emitter.sync_interval_in_seconds:
  description: Interval to sync routes to the router in seconds.
  default: 60
diego.ssh_proxy.allowed_ciphers:
  description: Comma separated list of allowed cipher algorithms
  default: null
diego.ssh_proxy.allowed_keyexchanges:
  description: Comma separated list of allowed key exchange algorithms
  default: null
diego.ssh_proxy.allowed_macs:
  description: Comma separated list of allowed MAC algorithms
  default: null
diego.ssh_proxy.bbs.api_location:
  description: Address to the BBS Server
  default: bbs.service.cf.internal:8889
diego.ssh_proxy.bbs.ca_cert:
  description: PEM-encoded CA certificate
  default: null
diego.ssh_proxy.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
diego.ssh_proxy.bbs.client_key:
  description: PEM-encoded client key
  default: null
diego.ssh_proxy.bbs.client_session_cache_size:
  description: capacity of the tls client cache
  default: null
diego.ssh_proxy.bbs.max_idle_conns_per_host:
  description: maximum number of idle http connections
  default: null
diego.ssh_proxy.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
diego.ssh_proxy.cc.external_port:
  description: External port of the Cloud Controller API
  default: 9022
diego.ssh_proxy.cc.internal_service_hostname:
  description: Internal service hostname of Cloud Controller Api
  default: cloud-controller-ng.service.cf.internal
diego.ssh_proxy.debug_addr:
  description: address at which to serve debug info
  default: 0.0.0.0:17016
diego.ssh_proxy.diego_credentials:
  description: Diego Credentials to be used with the Diego authenitcation method
  default: null
diego.ssh_proxy.dropsonde_port:
  description: local metron agent's port
  default: 3457
diego.ssh_proxy.enable_cf_auth:
  description: Allow ssh access for cf applications
  default: false
diego.ssh_proxy.enable_diego_auth:
  description: Allow ssh access for diego applications
  default: false
diego.ssh_proxy.host_key:
  description: PEM encoded RSA private key used to identify host
  default: null
diego.ssh_proxy.listen_addr:
  description: address for the proxy to listen on
  default: 0.0.0.0:2222
diego.ssh_proxy.log_level:
  description: Log level
  default: info
diego.ssh_proxy.uaa_secret:
  description: The oauth client secret used to authenticate the ssh-proxy with the
    uaa
  default: null
diego.ssh_proxy.uaa_token_url:
  description: URL of the UAA token endpoint
  default: null
diego.ssl.skip_cert_verify:
  description: when connecting over https, ignore bad ssl certificates
  default: false
vizzini.bbs.api_location:
  description: The address of the BBS
  default: bbs.service.cf.internal:8889
vizzini.bbs.client_cert:
  description: PEM-encoded client certificate
  default: null
vizzini.bbs.client_key:
  description: PEM-encoded client key
  default: null
vizzini.bbs.require_ssl:
  description: enable ssl for all communication with the bbs
  default: true
vizzini.eventually_timeout:
  description: default timeout for ginkgo assertions
  default: null
vizzini.nodes:
  description: The number of nodes to run the tests with
  default: 4
vizzini.routable_domain_suffix:
  description: The deployment's routable domain name
  default: null
vizzini.ssh.proxy_address:
  description: Host and port for the SSH proxy
  default: ssh-proxy.service.cf.internal:2222
vizzini.ssh.proxy_secret:
  description: Shared secret for the SSH proxy's Diego authenticator
  default: null
vizzini.verbose:
  description: Run tests in verbose mode
  default: false

