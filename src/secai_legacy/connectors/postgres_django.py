"""
PostgreSQL / Django Database Connector

Connects to Django-managed PostgreSQL database to fetch:
- Ticket details and metadata
- IOC catalog entries
- Historical ticket statistics
- IDS (Snort) results
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


@dataclass
class TicketData:
    """Ticket information from the database."""
    id: str
    created_at: datetime
    status: str
    severity: str
    outcome: str
    trigger_type: str
    trigger_value: str
    trigger_timestamp: datetime  # T0


@dataclass
class IOCData:
    """IOC catalog entry."""
    ioc_type: str
    ioc_value: str
    threat_group: Optional[str]
    confidence: float
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]


@dataclass
class HistoricalStats:
    """Historical ticket statistics for an IOC."""
    total_tickets: int
    threat_count: int
    false_positive_count: int
    threat_ratio: Optional[float]
    last_observed_ticket: Optional[datetime]


class PostgresDjangoConnector:
    """
    Connector for PostgreSQL database managed by Django.
    
    Retrieves ticket information, IOC catalog, and historical statistics.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize connector with configuration.
        
        Args:
            config: PostgreSQL configuration from config.yaml
        """
        self.config = config
        self.connection = None
        self._tables = config.get('tables', {})
        self._ticket_cols = config.get('ticket_columns', {})
        self._ioc_cols = config.get('ioc_columns', {})
    
    def connect(self) -> None:
        """Establish database connection."""
        try:
            self.connection = psycopg2.connect(
                host=self.config['host'],
                port=self.config['port'],
                database=self.config['database'],
                user=self.config.get('username', ''),
                password=self.config.get('password', '')
            )
            logger.info("Successfully connected to PostgreSQL database")
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise
    
    def disconnect(self) -> None:
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
            logger.info("Disconnected from PostgreSQL database")
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False
    
    def get_ticket(self, ticket_id: str) -> Optional[TicketData]:
        """
        Fetch ticket details by ID.
        
        Args:
            ticket_id: Unique ticket identifier
            
        Returns:
            TicketData object or None if not found
        """
        table = self._tables.get('tickets', 'tickets_ticket')
        cols = self._ticket_cols
        
        query = f"""
            SELECT 
                {cols.get('id', 'id')} as id,
                {cols.get('created_at', 'created_at')} as created_at,
                {cols.get('status', 'status')} as status,
                {cols.get('severity', 'severity')} as severity,
                {cols.get('outcome', 'outcome')} as outcome,
                {cols.get('trigger_type', 'trigger_type')} as trigger_type,
                {cols.get('trigger_value', 'trigger_value')} as trigger_value,
                {cols.get('trigger_timestamp', 'trigger_timestamp')} as trigger_timestamp
            FROM {table}
            WHERE {cols.get('id', 'id')} = %s
        """
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (ticket_id,))
                row = cursor.fetchone()
                
                if row:
                    return TicketData(
                        id=str(row['id']),
                        created_at=row['created_at'],
                        status=row['status'],
                        severity=row['severity'],
                        outcome=row['outcome'] or 'Unset',
                        trigger_type=row['trigger_type'],
                        trigger_value=row['trigger_value'],
                        trigger_timestamp=row['trigger_timestamp']
                    )
                return None
        except psycopg2.Error as e:
            logger.error(f"Error fetching ticket {ticket_id}: {e}")
            raise
    
    def get_ioc_info(self, ioc_type: str, ioc_value: str) -> Optional[IOCData]:
        """
        Lookup IOC in the catalog.
        
        Args:
            ioc_type: Type of indicator (domain, ip, hash, etc.)
            ioc_value: The indicator value
            
        Returns:
            IOCData object or None if not found
        """
        table = self._tables.get('ioc_catalog', 'ioc_ioccatalog')
        cols = self._ioc_cols
        
        query = f"""
            SELECT 
                {cols.get('ioc_type', 'ioc_type')} as ioc_type,
                {cols.get('ioc_value', 'ioc_value')} as ioc_value,
                {cols.get('threat_group', 'threat_group_id')} as threat_group,
                {cols.get('confidence', 'confidence')} as confidence,
                {cols.get('first_seen', 'first_seen')} as first_seen,
                {cols.get('last_seen', 'last_seen')} as last_seen
            FROM {table}
            WHERE {cols.get('ioc_type', 'ioc_type')} = %s
              AND {cols.get('ioc_value', 'ioc_value')} = %s
        """
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (ioc_type, ioc_value))
                row = cursor.fetchone()
                
                if row:
                    return IOCData(
                        ioc_type=row['ioc_type'],
                        ioc_value=row['ioc_value'],
                        threat_group=row.get('threat_group'),
                        confidence=float(row.get('confidence', 0.0)),
                        first_seen=row.get('first_seen'),
                        last_seen=row.get('last_seen')
                    )
                return None
        except psycopg2.Error as e:
            logger.error(f"Error fetching IOC {ioc_type}:{ioc_value}: {e}")
            raise
    
    def get_historical_stats(self, ioc_type: str, ioc_value: str, 
                             exclude_ticket_id: Optional[str] = None) -> HistoricalStats:
        """
        Calculate historical ticket statistics for an IOC.
        
        Args:
            ioc_type: Type of indicator
            ioc_value: The indicator value
            exclude_ticket_id: Optional ticket ID to exclude from stats
            
        Returns:
            HistoricalStats with TP/FP counts and ratio
        """
        table = self._tables.get('tickets', 'tickets_ticket')
        cols = self._ticket_cols
        
        exclude_clause = ""
        params: List[Any] = [ioc_type, ioc_value]
        
        if exclude_ticket_id:
            exclude_clause = f"AND {cols.get('id', 'id')} != %s"
            params.append(exclude_ticket_id)
        
        query = f"""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN {cols.get('outcome', 'outcome')} = 'Threat' THEN 1 ELSE 0 END) as threat_count,
                SUM(CASE WHEN {cols.get('outcome', 'outcome')} = 'False Positive' THEN 1 ELSE 0 END) as fp_count,
                MAX({cols.get('created_at', 'created_at')}) as last_observed
            FROM {table}
            WHERE {cols.get('trigger_type', 'trigger_type')} = %s
              AND {cols.get('trigger_value', 'trigger_value')} = %s
              {exclude_clause}
        """
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()
                
                total = row['total'] or 0
                tp = row['threat_count'] or 0
                fp = row['fp_count'] or 0
                
                # Calculate threat ratio
                resolved = tp + fp
                ratio = tp / resolved if resolved > 0 else None
                
                return HistoricalStats(
                    total_tickets=total,
                    threat_count=tp,
                    false_positive_count=fp,
                    threat_ratio=ratio,
                    last_observed_ticket=row.get('last_observed')
                )
        except psycopg2.Error as e:
            logger.error(f"Error calculating historical stats: {e}")
            raise
    
    def get_ids_results(self, ticket_id: str) -> List[Dict[str, Any]]:
        """
        Fetch IDS (Snort) results associated with a ticket.
        
        Args:
            ticket_id: Ticket identifier
            
        Returns:
            List of IDS result records
        """
        table = self._tables.get('ids_results', 'ids_snortresult')
        
        query = f"""
            SELECT *
            FROM {table}
            WHERE ticket_id = %s
        """
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (ticket_id,))
                return [dict(row) for row in cursor.fetchall()]
        except psycopg2.Error as e:
            logger.error(f"Error fetching IDS results for ticket {ticket_id}: {e}")
            raise
