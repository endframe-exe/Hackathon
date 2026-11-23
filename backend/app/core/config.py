import os
from pathlib import Path
from dotenv import load_dotenv

# Locate and load .env file
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()


class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "PhishGuard AI")
    VERSION: str = os.getenv("VERSION", "1.0.0")
    API_PREFIX: str = os.getenv("API_PREFIX", "/api")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "true").lower() in ("true", "1", "t", "yes")

    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "phishguard-default-secret-key-change-in-prod")

    # MySQL 8.4 Persistence Layer (FR-04)
    MYSQL_HOST: str = os.getenv("MYSQL_HOST", "127.0.0.1")
    MYSQL_PORT: int = int(os.getenv("MYSQL_PORT", "3306"))
    MYSQL_USER: str = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD: str = os.getenv("MYSQL_PASSWORD", "your_password_here")
    MYSQL_DATABASE: str = os.getenv("MYSQL_DATABASE", "phishguard_db")
    ENABLE_HISTORY: bool = os.getenv("ENABLE_HISTORY", "true").lower() in ("true", "1", "t", "yes")

    @property
    def DATABASE_URL(self) -> str:
        explicit = os.getenv("DATABASE_URL")
        if explicit:
            return explicit
        return (
            f"mysql+pymysql://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}"
            f"@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DATABASE}"
        )

    # VirusTotal API v3 (FR-01, Section 9)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "your_vt_api_key_here")
    VIRUSTOTAL_BASE_URL: str = os.getenv("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3")
    VIRUSTOTAL_TIMEOUT_SECONDS: float = float(os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS", "5.0"))


settings = Settings()
