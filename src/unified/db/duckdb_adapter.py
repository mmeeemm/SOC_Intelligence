"""
DuckDB Adapter for SOC_Intelligence

Fast local database for TOON events, tickets, and analysis results.
Optimized for PCAP analysis workflow.
"""

import duckdb
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime
import logging

from src.unified.models.schemas import TOONEvent, Ticket, IOC, TTP

logger = logging.getLogger(__name__)


class DuckDBAdapter:
    """
    DuckDB database adapter for SOC_Intelligence
   
    Features:
    - TOON events storage
    - Ticket tracking
    - IOC database
    - Fast analytics queries
    - Connection pooling
    """
    
    def __init__(self, db_path: str = "data/soc_intelligence.duckdb"):
        """Initialize DuckDB connection"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Connect and create tables if needed"""
        self.conn = duckdb.connect(str(self.db_path))
        self._create_tables()
        logger.info(f"DuckDB initialized: {self.db_path}")
    
    def _create_tables(self):
        """Create schema if not exists"""
        
        # TOON Events table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS toon_events (
                id INTEGER PRIMARY KEY,
                t DOUBLE NOT NULL,
                si VARCHAR,
                sp INTEGER,
                di VARCHAR,
                dp INTEGER,
                pr VARCHAR NOT NULL,
                bytes_sent BIGINT,
                bytes_recv BIGINT,
                packets_sent INTEGER,
                packets_recv INTEGER,
                duration DOUBLE,
                dns_query VARCHAR,
                dns_response VARCHAR,  -- JSON array
                http_method VARCHAR,
                http_host VARCHAR,
                http_uri VARCHAR,
                http_user_agent VARCHAR,
                http_status INTEGER,
                tls_sni VARCHAR,
                tls_ja3 VARCHAR,
                tls_version VARCHAR,
                zeek_uid VARCHAR,
                zeek_service VARCHAR,
                zeek_conn_state VARCHAR,
                alert_sid INTEGER,
                alert_msg VARCHAR,
                alert_priority INTEGER,
                alert_class VARCHAR,
                ingestion_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_file VARCHAR
            )
        """)
        
        # Tickets table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                ticket_id VARCHAR PRIMARY KEY,
                ioc_type VARCHAR NOT NULL,
                ioc_value VARCHAR NOT NULL,
                trigger_type VARCHAR NOT NULL,
                created_at TIMESTAMP NOT NULL,
                window_start TIMESTAMP NOT NULL,
                window_end TIMESTAMP NOT NULL,
                verdict VARCHAR,
                severity VARCHAR,
                confidence DOUBLE,
                tp_count INTEGER DEFAULT 0,
                fp_count INTEGER DEFAULT 0,
                historical_threat_ratio DOUBLE,
                report_path VARCHAR,
                report_generated TIMESTAMP
            )
        """)
        
        # IOCs table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_type VARCHAR NOT NULL,
                ioc_value VARCHAR NOT NULL,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                sightings INTEGER DEFAULT 0,
                threat_score DOUBLE DEFAULT 0.0,
                sources VARCHAR,  -- JSON array
                PRIMARY KEY (ioc_type, ioc_value)
            )
        """)
        
        # TTPs table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS ttps (
                id INTEGER PRIMARY KEY,
                ticket_id VARCHAR NOT NULL,
                technique_id VARCHAR NOT NULL,
                technique_name VARCHAR NOT NULL,
                tactic VARCHAR NOT NULL,
                confidence VARCHAR NOT NULL,
                evidence VARCHAR,  -- JSON array
                mitigations VARCHAR,  -- JSON array
                FOREIGN KEY (ticket_id) REFERENCES tickets(ticket_id)
            )
        """)
        
        # Create indexes for performance
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_toon_t ON toon_events(t)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_toon_si ON toon_events(si)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_toon_di ON toon_events(di)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_toon_pr ON toon_events(pr)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_ioc ON tickets(ioc_value)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_created ON tickets(created_at)")
        
        logger.info("DuckDB schema created/verified")
    
    def insert_events(self, events: List[TOONEvent]) -> int:
        """
        Bulk insert TOON events
        
        Returns:
            Number of events inserted
        """
        if not events:
            return 0
        
        # Convert to dict for DuckDB
        records = []
        for event in events:
            record = event.dict(exclude_none=False)
            # Convert lists to JSON strings
            if record.get('dns_response'):
                import json
                record['dns_response'] = json.dumps(record['dns_response'])
            records.append(record)
        
        # Use DuckDB's efficient bulk insert
        self.conn.executemany("""
            INSERT INTO toon_events (
                t, si, sp, di, dp, pr, bytes_sent, bytes_recv, packets_sent, packets_recv,
                duration, dns_query, dns_response, http_method, http_host, http_uri,
                http_user_agent, http_status, tls_sni, tls_ja3, tls_version,
                zeek_uid, zeek_service, zeek_conn_state,
                alert_sid, alert_msg, alert_priority, alert_class,
                ingestion_time, source_file
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, [
            (
                r['t'], r.get('si'), r.get('sp'), r.get('di'), r.get('dp'), r['pr'],
                r.get('bytes_sent'), r.get('bytes_recv'), r.get('packets_sent'), r.get('packets_recv'),
                r.get('duration'), r.get('dns_query'), r.get('dns_response'),
                r.get('http_method'), r.get('http_host'), r.get('http_uri'),
                r.get('http_user_agent'), r.get('http_status'),
                r.get('tls_sni'), r.get('tls_ja3'), r.get('tls_version'),
                r.get('zeek_uid'), r.get('zeek_service'), r.get('zeek_conn_state'),
                r.get('alert_sid'), r.get('alert_msg'), r.get('alert_priority'), r.get('alert_class'),
                r['ingestion_time'], r.get('source_file')
            ) for r in records
        ])
        
        logger.info(f"Inserted {len(events)} TOON events")
        return len(events)
    
    def query_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        limit: int = 10000
    ) -> List[TOONEvent]:
        """Query TOON events with filters"""
        
        conditions = []
        params = []
        
        if start_time:
            conditions.append("t >= ?")
            params.append(start_time.timestamp())
        
        if end_time:
            conditions.append("t <= ?")
            params.append(end_time.timestamp())
        
        if src_ip:
            conditions.append("si = ?")
            params.append(src_ip)
        
        if dst_ip:
            conditions.append("di = ?")
            params.append(dst_ip)
        
        if protocol:
            conditions.append("pr = ?")
            params.append(protocol.lower())
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        query = f"""
            SELECT * FROM toon_events
            WHERE {where_clause}
            ORDER BY t DESC
            LIMIT ?
        """
        params.append(limit)
        
        results = self.conn.execute(query, params).fetchall()
        
        # Convert to TOONEvent objects
        events = []
        columns = [desc[0] for desc in self.conn.description]
        for row in results:
            data = dict(zip(columns, row))
            # Parse JSON fields
            if data.get('dns_response'):
                import json
                data['dns_response'] = json.loads(data['dns_response'])
            events.append(TOONEvent(**data))
        
        return events
    
    def create_ticket(self, ticket: Ticket) -> None:
        """Create a new SOC ticket"""
        import json
        
        self.conn.execute("""
            INSERT INTO tickets (
                ticket_id, ioc_type, ioc_value, trigger_type,
                created_at, window_start, window_end,
                verdict, severity, confidence,
                tp_count, fp_count, historical_threat_ratio,
                report_path, report_generated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ticket.ticket_id,
            ticket.ioc.ioc_type,
            ticket.ioc.ioc_value,
            ticket.trigger_type,
            ticket.created_at,
            ticket.window_start,
            ticket.window_end,
            ticket.verdict,
            ticket.severity,
            ticket.confidence,
            ticket.tp_count,
            ticket.fp_count,
            ticket.historical_threat_ratio,
            ticket.report_path,
            ticket.report_generated
        ))
        
        logger.info(f"Created ticket: {ticket.ticket_id}")
    
    def get_historical_stats(self, ioc_value: str) -> Dict[str, Any]:
        """
        Get historical statistics for an IOC (for 75/25 weighting)
        
        Returns:
            {
                "total_tickets": int,
                "tp_count": int,
                "fp_count": int,
                "threat_ratio": float,
                "last_seen": datetime
            }
        """
        result = self.conn.execute("""
            SELECT
                COUNT(*) as total_tickets,
                SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END) as tp_count,
                SUM(CASE WHEN verdict = 'BENIGN' THEN 1 ELSE 0 END) as fp_count,
                MAX(created_at) as last_seen
            FROM tickets
            WHERE ioc_value = ?
        """, [ioc_value]).fetchone()
        
        total, tp, fp, last_seen = result
        
        threat_ratio = tp / (tp + fp) if (tp + fp) > 0 else 0.5  # Neutral default
        
        return {
            "total_tickets": total or 0,
            "tp_count": tp or 0,
            "fp_count": fp or 0,
            "threat_ratio": threat_ratio,
            "last_seen": last_seen,
            "historical_score": threat_ratio  # For 75/25 calculation
        }
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """Get protocol distribution for current dataset"""
        results = self.conn.execute("""
            SELECT pr, COUNT(*) as count
            FROM toon_events
            GROUP BY pr
            ORDER BY count DESC
        """).fetchall()
        
        return {row[0]: row[1] for row in results}
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("DuckDB connection closed")
