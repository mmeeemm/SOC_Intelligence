
import logging
import duckdb
import pandas as pd
from pathlib import Path

logger = logging.getLogger(__name__)

class DatabaseClient:
    """
    Singleton DuckDB Client.
    Manages the connection to the accelerated analytics database.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseClient, cls).__new__(cls)
            cls._instance.db_path = "blink_phoenix.duckdb"
            cls._instance.conn = None
            cls._instance._connect()
        return cls._instance

    def _connect(self):
        """Establish connection to DuckDB."""
        try:
            self.conn = duckdb.connect(self.db_path)
            logger.info(f"Connected to DuckDB: {self.db_path}")

            # MAXIMUM PERFORMANCE: 100GB RAM / 20 Cores Allocation
            self.conn.execute("SET memory_limit = '100GB';")
            self.conn.execute("SET threads = 20;")
            self.conn.execute("SET preserve_insertion_order = false;")
            self.conn.execute("PRAGMA temp_directory='/tmp/duckdb_max_cache';")
            self.conn.execute("SET max_temp_directory_size = '2TB';") # Use the 3TB NVMe!
            self.conn.execute("SET enable_object_cache = true;")
            self.conn.execute("SET default_order = 'DESC';")
            # Broad search path to prevent "Did you mean blink_phoenix.events?" errors
            self.conn.execute("SET search_path = 'main,blink_phoenix';")

            # Performance Tuning
            logger.info("DuckDB Performance PRAGMAs initialized.")

        except Exception as e:
            logger.error(f"DuckDB Connection Failed: {e}")
            raise

    def initialize_schema(self):
        """
        Surgically ensures all tables and indexes exist.
        Prevents CatalogErrors by checking existence before index creation.
        """
        from src.data.schema import DDL_EVENTS_TABLE, DDL_ASSETS_TABLE, DDL_REPUTATION_TABLE

        try:
            # 1. Ensure Tables Exist
            self.execute(DDL_EVENTS_TABLE)
            self.execute(DDL_ASSETS_TABLE)
            self.execute(DDL_REPUTATION_TABLE)

            # 2. Add Indexes (Only if tables are confirmed)
            self.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events (\"@timestamp\");")
            self.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON events (\"source.ip\");")
            self.execute("CREATE INDEX IF NOT EXISTS idx_community_id ON events (\"network.community_id\");")
            logger.info("[DONE] Database schema and high-performance indexes verified.")
        except Exception as e:
            logger.error(f"Schema Initialization Failed: {e}")

    def query(self, sql: str) -> pd.DataFrame:
        """Execute SQL and return Pandas DataFrame (via Arrow)."""
        if not self.conn:
            self._connect()

        try:
            return self.conn.execute(sql).df()
        except Exception as e:
            logger.error(f"Query Failed: {sql}\nError: {e}")
            return pd.DataFrame() # Return empty on error

    def execute(self, sql: str):
        """Execute DDL/DML statements."""
        if not self.conn:
            self._connect()
        try:
            self.conn.execute(sql)
            # self.conn.commit() # DuckDB is auto-commit by default or depends on connection
            logger.info(f"Executed: {sql[:100]}...")
        except Exception as e:
            logger.error(f"Execution Failed: {e}")
            raise

    def reset_database(self):
        """Hard Reset: Deletes all forensic archival data."""
        if not self.conn:
            self._connect()
        try:
            self.conn.execute("DROP TABLE IF EXISTS events")
            self.conn.execute("DROP TABLE IF EXISTS session_events")
            self.conn.execute("DROP TABLE IF EXISTS purified_events")
            self.conn.execute("DROP TABLE IF EXISTS assets")
            self.conn.execute("DROP TABLE IF EXISTS reputation")
            logger.info("PURGE Database hard reset complete. All forensic memory purged.")
            return True
        except Exception as e:
            logger.error(f"Reset Failed: {e}")
            return False

    def export_to_parquet(self, table_name: str, output_path: str):
        """Standard Forensic Export: Save table to Parquet format."""
        if not self.conn:
            self._connect()
        try:
            sql = f"COPY {table_name} TO '{output_path}' (FORMAT PARQUET);"
            self.conn.execute(sql)
            logger.info(f"[DONE] Exported {table_name} to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Parquet Export Failed: {e}")
            return False

# Global Instance
db = DatabaseClient()
