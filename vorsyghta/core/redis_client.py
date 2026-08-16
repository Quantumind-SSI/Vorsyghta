"""Shared Redis client factory for Vorsyghta.

Handles both standalone and clustered Redis deployments (e.g. Azure Redis
Enterprise Cluster), automatically following MOVED/ASK redirects in cluster mode.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional, Union

import redis as redis_lib

logger = logging.getLogger(__name__)

# Type alias — both Redis and RedisCluster expose the same command interface
RedisClient = Union[redis_lib.Redis, "redis_lib.cluster.RedisCluster"]

_client: Optional[RedisClient] = None


def get_redis_client() -> Optional[RedisClient]:
    """Lazily create a Redis client from REDIS_URL.

    Uses ``RedisCluster`` when the server is a Redis Cluster (handles MOVED/ASK
    redirects automatically), and a standalone ``Redis`` client otherwise.

    Returns ``None`` if REDIS_URL is unset or the connection fails.
    """
    global _client
    if _client is not None:
        return _client

    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        logger.warning("REDIS_URL not set; Redis-dependent features will be disabled")
        return None

    # Try cluster client first (handles Azure Redis Enterprise Cluster redirects)
    try:
        from redis.cluster import RedisCluster

        _client = RedisCluster.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            ssl_check_hostname=False,
        )
        _client.ping()
        logger.info("Redis client connected (cluster mode)")
        return _client
    except Exception as cluster_exc:
        logger.debug("Redis cluster connection failed (%s); trying standalone", cluster_exc)

    # Fall back to standalone client (single-node Redis, non-clustered)
    try:
        _client = redis_lib.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=5,
            ssl_check_hostname=False,
        )
        _client.ping()
        logger.info("Redis client connected (standalone mode)")
        return _client
    except Exception as exc:
        logger.warning("Redis unavailable (%s); Redis-dependent features disabled", exc)
        _client = None
        return None
