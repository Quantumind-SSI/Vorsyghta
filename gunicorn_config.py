import multiprocessing

bind = "0.0.0.0:8000"
workers = 4
threads = 2
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
accesslog = "-"
errorlog = "-"
loglevel = "info"
preload_app = True
