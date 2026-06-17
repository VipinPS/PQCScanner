from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str  = "postgresql://pqc_user:pqc_pass@localhost:5432/pqc_platform"
    REDIS_URL: str     = "redis://localhost:6379/0"

    # Git provider tokens
    GITHUB_TOKEN: str            = ""   # ghp_xxx  or  github_pat_xxx  (github.com)
    GITHUB_ENTERPRISE_TOKEN: str = ""   # PAT for self-hosted GitHub Enterprise (github.yourco.com)
    GITLAB_TOKEN: str            = ""   # glpat_xxx
    BITBUCKET_TOKEN: str         = ""   # Bitbucket app password (user:app_password)
    GITEA_TOKEN: str             = ""   # Self-hosted Gitea token

    # SSH key path (alternative to token auth)
    SSH_KEY_PATH: str     = ""   # e.g. /run/secrets/id_rsa

    SCAN_WORKERS: int     = 4
    SECRET_KEY: str       = "change-me-in-production"

    class Config:
        env_file = ".env"

settings = Settings()
