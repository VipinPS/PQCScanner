from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
import os
import logging

logger = logging.getLogger(__name__)

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def run_migrations():
    """
    Auto-apply any pending SQL migration files from the migrations/ directory.
    Tracks applied migrations in a schema_migrations table so each file
    runs exactly once, even across container restarts.
    """
    migrations_dir = os.path.join(os.path.dirname(__file__), "..", "..", "migrations")
    migrations_dir = os.path.abspath(migrations_dir)

    if not os.path.isdir(migrations_dir):
        logger.warning("Migrations directory not found: %s", migrations_dir)
        return

    with engine.connect() as conn:
        # Create tracking table if it doesn't exist
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                filename   VARCHAR PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT NOW()
            )
        """))
        conn.commit()

        # Find already-applied migrations
        applied = {
            row[0] for row in conn.execute(
                text("SELECT filename FROM schema_migrations")
            )
        }

        # Collect and sort pending migration files
        sql_files = sorted(
            f for f in os.listdir(migrations_dir)
            if f.endswith(".sql")
        )
        pending = [f for f in sql_files if f not in applied]

        if not pending:
            logger.info("Database schema is up to date (%d migrations applied)", len(applied))
            return

        logger.info("Applying %d pending migration(s)...", len(pending))

        for filename in pending:
            filepath = os.path.join(migrations_dir, filename)
            try:
                with open(filepath, encoding="utf-8") as fh:
                    sql = fh.read()

                conn.execute(text(sql))
                conn.execute(
                    text("INSERT INTO schema_migrations (filename) VALUES (:f)"),
                    {"f": filename},
                )
                conn.commit()
                logger.info("  ✓ Applied: %s", filename)

            except Exception as e:
                conn.rollback()
                logger.error("  ✗ Failed:  %s — %s", filename, e)
                raise RuntimeError(f"Migration failed: {filename}") from e
