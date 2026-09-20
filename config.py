"""Environment-specific application configuration."""

import os


class Config:
    SECRET_KEY = os.environ.get("WEBTRUST_SECRET_KEY", "webtrust-development-key")
    MAX_CONTENT_LENGTH = 64 * 1024
    MAX_BATCH_SIZE = int(os.environ.get("WEBTRUST_MAX_BATCH_SIZE", "10"))
    MAX_REQUESTS_PER_MINUTE = int(
        os.environ.get("WEBTRUST_MAX_REQUESTS_PER_MINUTE", "20")
    )
    CACHE_TTL_SECONDS = int(os.environ.get("WEBTRUST_CACHE_TTL_SECONDS", "300"))
    DATABASE_FILE = os.environ.get("WEBTRUST_DATABASE", "webtrust.sqlite3")
    LOG_FILE = os.environ.get("WEBTRUST_LOG_FILE", "webtrust.log")
    TESTING = False


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "webtrust-test-key"
    DATABASE_FILE = ":memory:"
    LOG_FILE = "webtrust-test.log"
