"""Bounded synchronous workers behind the local TLS proxy."""
bind = "127.0.0.1:8766"
workers = 2
worker_class = "sync"
timeout = 30
graceful_timeout = 20
max_requests = 1000
max_requests_jitter = 100
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190
# The application verifies the peer + exact X-Forwarded-Proto itself.
forwarded_allow_ips = ""
secure_scheme_headers = {}
accesslog = None
errorlog = "-"
