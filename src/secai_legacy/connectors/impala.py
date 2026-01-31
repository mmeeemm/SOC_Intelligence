"""
Impala Connector for Zeek Logs

Connects to Impala/Hue to query Zeek network logs.
Supports GSSAPI (Kerberos), PLAIN, and NOSASL authentication.
Returns aggregated data only - no raw log export to reports.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from impala.dbapi import connect as impala_connect
from impala.error import HiveServer2Error

logger = logging.getLogger(__name__)


@dataclass
class ZeekAggregates:
    """Aggregated Zeek log data for a time window."""
    total_sightings: int = 0
    distinct_src_ips: set = field(default_factory=set)
    distinct_dst_ips: set = field(default_factory=set)
    protocol_coverage: List[Dict[str, Any]] = field(default_factory=list)
    country_pairs: Dict[Tuple[str, str], int] = field(default_factory=dict)
    temporal_buckets: Dict[str, int] = field(default_factory=dict)
    fields_present: Dict[str, List[str]] = field(default_factory=dict)
    fields_used: Dict[str, List[str]] = field(default_factory=dict)
    sightings_by_log_type: Dict[str, int] = field(default_factory=dict)
    sightings_by_field: Dict[str, int] = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    protocol_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    peer_entities: List[Dict[str, Any]] = field(default_factory=list)


class ImpalaConnector:
    """
    Connector for Impala to query Zeek network logs.
    
    Performs aggregate queries within T0 ± 24h window.
    Does NOT export raw rows to reports.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize connector with configuration.
        
        Args:
            config: Impala configuration from config.yaml
        """
        self.config = config
        self.connection = None
        self.database = config.get('database', 'zeek_logs')
        self.log_tables = config.get('log_tables', [])
        self._common_cols = config.get('common_columns', {})
        self._dns_cols = config.get('dns_columns', {})
        self._http_cols = config.get('http_columns', {})
        self._ssl_cols = config.get('ssl_columns', {})
        self._smtp_cols = config.get('smtp_columns', {})
        self._ssh_cols = config.get('ssh_columns', {})
    
    def connect(self) -> None:
        """Establish connection to Impala."""
        auth = self.config.get('auth_mechanism', 'NOSASL')
        
        connect_params = {
            'host': self.config['host'],
            'port': self.config['port'],
            'database': self.database,
            'auth_mechanism': auth,
            'use_ssl': self.config.get('use_ssl', False)
        }
        
        # Add Kerberos params if using GSSAPI
        if auth == 'GSSAPI':
            kerberos_config = self.config.get('kerberos', {})
            connect_params['kerberos_service_name'] = kerberos_config.get('service_name', 'impala')
        
        try:
            self.connection = impala_connect(**connect_params)
            logger.info(f"Connected to Impala at {self.config['host']}:{self.config['port']}")
        except HiveServer2Error as e:
            logger.error(f"Failed to connect to Impala: {e}")
            raise
    
    def disconnect(self) -> None:
        """Close Impala connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
            logger.info("Disconnected from Impala")
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False
    
    def _get_table_columns(self, table_name: str) -> List[str]:
        """
        Get available columns for a Zeek log table.
        
        Args:
            table_name: Name of the log table
            
        Returns:
            List of column names
        """
        query = f"DESCRIBE {self.database}.{table_name}"
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(query)
            columns = [row[0] for row in cursor.fetchall()]
            cursor.close()
            return columns
        except HiveServer2Error as e:
            logger.warning(f"Could not describe table {table_name}: {e}")
            return []
    
    def _build_ioc_match_conditions(self, ioc_type: str, ioc_value: str, 
                                     table_name: str, available_cols: List[str]) -> List[Tuple[str, str]]:
        """
        Build WHERE conditions for IOC matching based on table type.
        
        Returns list of (condition_sql, matched_field) tuples.
        """
        conditions = []
        ts_col = self._common_cols.get('timestamp', 'ts')
        src_ip = self._common_cols.get('src_ip', 'id.orig_h')
        dst_ip = self._common_cols.get('dst_ip', 'id.resp_h')
        
        # IP-based matching
        if ioc_type == 'ip':
            if src_ip.replace('.', '_') in available_cols or src_ip in available_cols:
                conditions.append((f"`{src_ip}` = '{ioc_value}'", 'src_ip'))
            if dst_ip.replace('.', '_') in available_cols or dst_ip in available_cols:
                conditions.append((f"`{dst_ip}` = '{ioc_value}'", 'dst_ip'))
        
        # Domain-based matching
        elif ioc_type == 'domain':
            if table_name == 'dns':
                query_col = self._dns_cols.get('query', 'query')
                if query_col in available_cols:
                    conditions.append((f"`{query_col}` = '{ioc_value}' OR `{query_col}` LIKE '%.{ioc_value}'", 'dns.query'))
            
            if table_name == 'http':
                host_col = self._http_cols.get('host', 'host')
                if host_col in available_cols:
                    conditions.append((f"`{host_col}` = '{ioc_value}' OR `{host_col}` LIKE '%.{ioc_value}'", 'http.host'))
            
            if table_name == 'ssl':
                sn_col = self._ssl_cols.get('server_name', 'server_name')
                if sn_col in available_cols:
                    conditions.append((f"`{sn_col}` = '{ioc_value}' OR `{sn_col}` LIKE '%.{ioc_value}'", 'ssl.server_name'))
        
        # URL matching
        elif ioc_type == 'url' and table_name == 'http':
            uri_col = self._http_cols.get('uri', 'uri')
            if uri_col in available_cols:
                conditions.append((f"`{uri_col}` LIKE '%{ioc_value}%'", 'http.uri'))
        
        # Email matching
        elif ioc_type == 'email' and table_name == 'smtp':
            mailfrom_col = self._smtp_cols.get('mailfrom', 'mailfrom')
            rcptto_col = self._smtp_cols.get('rcptto', 'rcptto')
            if mailfrom_col in available_cols:
                conditions.append((f"`{mailfrom_col}` = '{ioc_value}'", 'smtp.mailfrom'))
            if rcptto_col in available_cols:
                conditions.append((f"`{rcptto_col}` LIKE '%{ioc_value}%'", 'smtp.rcptto'))
        
        # Hash matching (file logs)
        elif ioc_type in ('md5', 'sha1', 'sha256') and table_name == 'files':
            if ioc_type in available_cols:
                conditions.append((f"`{ioc_type}` = '{ioc_value}'", f'files.{ioc_type}'))
        
        # User-agent matching
        elif ioc_type == 'user_agent' and table_name == 'http':
            ua_col = self._http_cols.get('user_agent', 'user_agent')
            if ua_col in available_cols:
                conditions.append((f"`{ua_col}` = '{ioc_value}'", 'http.user_agent'))
        
        return conditions
    
    def query_zeek_aggregates(self, ioc_type: str, ioc_value: str,
                               t0: datetime, window_hours: int = 24,
                               bucket_minutes: int = 15) -> ZeekAggregates:
        """
        Query Zeek logs and compute aggregates for IOC within time window.
        
        Args:
            ioc_type: Type of indicator
            ioc_value: The indicator value
            t0: Anchor timestamp (trigger time)
            window_hours: Hours before and after T0 to analyze
            bucket_minutes: Size of temporal buckets
            
        Returns:
            ZeekAggregates with all computed metrics
        """
        start_time = t0 - timedelta(hours=window_hours)
        end_time = t0 + timedelta(hours=window_hours)
        
        aggregates = ZeekAggregates()
        ts_col = self._common_cols.get('timestamp', 'ts')
        src_ip_col = self._common_cols.get('src_ip', 'id_orig_h')
        dst_ip_col = self._common_cols.get('dst_ip', 'id_resp_h')
        src_country_col = self._common_cols.get('src_country', 'src_country')
        dst_country_col = self._common_cols.get('dst_country', 'dst_country')
        
        for table_name in self.log_tables:
            try:
                # Get available columns
                columns = self._get_table_columns(table_name)
                if not columns:
                    continue
                
                aggregates.fields_present[table_name] = columns
                
                # Get IOC matching conditions
                conditions = self._build_ioc_match_conditions(ioc_type, ioc_value, table_name, columns)
                if not conditions:
                    continue
                
                # Track fields used
                fields_used = []
                
                for condition_sql, matched_field in conditions:
                    # Build aggregate query
                    query = f"""
                        SELECT 
                            COUNT(*) as cnt,
                            COUNT(DISTINCT `{src_ip_col}`) as distinct_src,
                            COUNT(DISTINCT `{dst_ip_col}`) as distinct_dst,
                            MIN(`{ts_col}`) as first_seen,
                            MAX(`{ts_col}`) as last_seen
                        FROM {self.database}.{table_name}
                        WHERE `{ts_col}` >= '{start_time.isoformat()}'
                          AND `{ts_col}` <= '{end_time.isoformat()}'
                          AND ({condition_sql})
                    """
                    
                    cursor = self.connection.cursor()
                    cursor.execute(query)
                    row = cursor.fetchone()
                    cursor.close()
                    
                    if row and row[0] > 0:
                        cnt, distinct_src, distinct_dst, first, last = row
                        
                        aggregates.total_sightings += cnt
                        aggregates.sightings_by_log_type[table_name] = \
                            aggregates.sightings_by_log_type.get(table_name, 0) + cnt
                        aggregates.sightings_by_field[matched_field] = \
                            aggregates.sightings_by_field.get(matched_field, 0) + cnt
                        
                        fields_used.append(matched_field)
                        
                        # Update first/last seen
                        if first:
                            if aggregates.first_seen is None or first < aggregates.first_seen:
                                aggregates.first_seen = first
                        if last:
                            if aggregates.last_seen is None or last > aggregates.last_seen:
                                aggregates.last_seen = last
                        
                        # Get distinct IPs
                        self._collect_distinct_ips(aggregates, table_name, src_ip_col, 
                                                   dst_ip_col, ts_col, start_time, 
                                                   end_time, condition_sql)
                        
                        # Get country pair distribution
                        if src_country_col in columns and dst_country_col in columns:
                            self._collect_country_pairs(aggregates, table_name, 
                                                        src_country_col, dst_country_col,
                                                        ts_col, start_time, end_time, 
                                                        condition_sql)
                        
                        # Get temporal distribution
                        self._collect_temporal_distribution(aggregates, table_name,
                                                            ts_col, start_time, end_time,
                                                            condition_sql, bucket_minutes)
                        
                        # Collect protocol-specific details
                        self._collect_protocol_details(aggregates, table_name, columns,
                                                       ts_col, start_time, end_time,
                                                       condition_sql)
                        
                        # Add to protocol coverage
                        aggregates.protocol_coverage.append({
                            'protocol': self._get_protocol_for_table(table_name),
                            'zeek_log_type': table_name,
                            'sightings': cnt,
                            'distinct_src_ip': distinct_src,
                            'distinct_dst_ip': distinct_dst,
                            'matched_fields_used': [matched_field]
                        })
                
                if fields_used:
                    aggregates.fields_used[table_name] = fields_used
                    
            except HiveServer2Error as e:
                logger.warning(f"Error querying {table_name}: {e}")
                continue
        
        # Compute peer entity summary
        self._compute_peer_summary(aggregates)
        
        return aggregates
    
    def _collect_distinct_ips(self, aggregates: ZeekAggregates, table_name: str,
                               src_ip_col: str, dst_ip_col: str, ts_col: str,
                               start_time: datetime, end_time: datetime,
                               condition_sql: str) -> None:
        """Collect distinct source and destination IPs."""
        # Source IPs
        query = f"""
            SELECT DISTINCT `{src_ip_col}`
            FROM {self.database}.{table_name}
            WHERE `{ts_col}` >= '{start_time.isoformat()}'
              AND `{ts_col}` <= '{end_time.isoformat()}'
              AND ({condition_sql})
            LIMIT 1000
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(query)
            for row in cursor.fetchall():
                if row[0]:
                    aggregates.distinct_src_ips.add(row[0])
            cursor.close()
        except HiveServer2Error:
            pass
        
        # Destination IPs
        query = f"""
            SELECT DISTINCT `{dst_ip_col}`
            FROM {self.database}.{table_name}
            WHERE `{ts_col}` >= '{start_time.isoformat()}'
              AND `{ts_col}` <= '{end_time.isoformat()}'
              AND ({condition_sql})
            LIMIT 1000
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(query)
            for row in cursor.fetchall():
                if row[0]:
                    aggregates.distinct_dst_ips.add(row[0])
            cursor.close()
        except HiveServer2Error:
            pass
    
    def _collect_country_pairs(self, aggregates: ZeekAggregates, table_name: str,
                                src_country_col: str, dst_country_col: str,
                                ts_col: str, start_time: datetime, 
                                end_time: datetime, condition_sql: str) -> None:
        """Collect country pair distribution."""
        query = f"""
            SELECT `{src_country_col}`, `{dst_country_col}`, COUNT(*) as cnt
            FROM {self.database}.{table_name}
            WHERE `{ts_col}` >= '{start_time.isoformat()}'
              AND `{ts_col}` <= '{end_time.isoformat()}'
              AND ({condition_sql})
            GROUP BY `{src_country_col}`, `{dst_country_col}`
            ORDER BY cnt DESC
            LIMIT 100
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(query)
            for row in cursor.fetchall():
                src_c, dst_c, cnt = row
                key = (src_c or 'Unknown', dst_c or 'Unknown')
                aggregates.country_pairs[key] = aggregates.country_pairs.get(key, 0) + cnt
            cursor.close()
        except HiveServer2Error:
            pass
    
    def _collect_temporal_distribution(self, aggregates: ZeekAggregates, 
                                        table_name: str, ts_col: str,
                                        start_time: datetime, end_time: datetime,
                                        condition_sql: str, bucket_minutes: int) -> None:
        """Collect temporal distribution in buckets."""
        # Use Impala's date_trunc or manual bucketing
        query = f"""
            SELECT 
                FROM_TIMESTAMP(
                    DATE_TRUNC('HOUR', `{ts_col}`),
                    'yyyy-MM-dd HH:00'
                ) as bucket,
                COUNT(*) as cnt
            FROM {self.database}.{table_name}
            WHERE `{ts_col}` >= '{start_time.isoformat()}'
              AND `{ts_col}` <= '{end_time.isoformat()}'
              AND ({condition_sql})
            GROUP BY bucket
            ORDER BY bucket
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(query)
            for row in cursor.fetchall():
                bucket_key, cnt = row
                if bucket_key:
                    aggregates.temporal_buckets[str(bucket_key)] = \
                        aggregates.temporal_buckets.get(str(bucket_key), 0) + cnt
            cursor.close()
        except HiveServer2Error:
            pass
    
    def _collect_protocol_details(self, aggregates: ZeekAggregates,
                                   table_name: str, columns: List[str],
                                   ts_col: str, start_time: datetime,
                                   end_time: datetime, condition_sql: str) -> None:
        """Collect protocol-specific aggregate details."""
        
        if table_name == 'dns':
            details = self._get_dns_details(columns, ts_col, start_time, end_time, condition_sql)
            if details:
                aggregates.protocol_details['dns'] = details
        
        elif table_name == 'http':
            details = self._get_http_details(columns, ts_col, start_time, end_time, condition_sql)
            if details:
                aggregates.protocol_details['http'] = details
        
        elif table_name == 'ssl':
            details = self._get_ssl_details(columns, ts_col, start_time, end_time, condition_sql)
            if details:
                aggregates.protocol_details['tls'] = details
        
        elif table_name == 'smtp':
            details = self._get_smtp_details(columns, ts_col, start_time, end_time, condition_sql)
            if details:
                aggregates.protocol_details['smtp'] = details
    
    def _get_dns_details(self, columns: List[str], ts_col: str,
                          start_time: datetime, end_time: datetime,
                          condition_sql: str) -> Dict[str, Any]:
        """Get DNS-specific aggregates."""
        details = {}
        query_col = self._dns_cols.get('query', 'query')
        qtype_col = self._dns_cols.get('query_type', 'qtype_name')
        rcode_col = self._dns_cols.get('rcode', 'rcode_name')
        
        try:
            # Unique queries
            if query_col in columns:
                query = f"""
                    SELECT COUNT(DISTINCT `{query_col}`)
                    FROM {self.database}.dns
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                row = cursor.fetchone()
                details['unique_queries'] = row[0] if row else 0
                cursor.close()
            
            # Query types distribution
            if qtype_col in columns:
                query = f"""
                    SELECT `{qtype_col}`, COUNT(*) as cnt
                    FROM {self.database}.dns
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                    GROUP BY `{qtype_col}`
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                details['query_types'] = {row[0]: row[1] for row in cursor.fetchall() if row[0]}
                cursor.close()
            
            # Response codes
            if rcode_col in columns:
                query = f"""
                    SELECT `{rcode_col}`, COUNT(*) as cnt
                    FROM {self.database}.dns
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                    GROUP BY `{rcode_col}`
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                details['response_codes'] = {row[0]: row[1] for row in cursor.fetchall() if row[0]}
                cursor.close()
                
        except HiveServer2Error:
            pass
        
        return details
    
    def _get_http_details(self, columns: List[str], ts_col: str,
                           start_time: datetime, end_time: datetime,
                           condition_sql: str) -> Dict[str, Any]:
        """Get HTTP-specific aggregates."""
        details = {}
        method_col = self._http_cols.get('method', 'method')
        status_col = self._http_cols.get('status_code', 'status_code')
        ua_col = self._http_cols.get('user_agent', 'user_agent')
        
        try:
            # HTTP methods
            if method_col in columns:
                query = f"""
                    SELECT `{method_col}`, COUNT(*) as cnt
                    FROM {self.database}.http
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                    GROUP BY `{method_col}`
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                details['methods'] = {row[0]: row[1] for row in cursor.fetchall() if row[0]}
                cursor.close()
            
            # Status codes
            if status_col in columns:
                query = f"""
                    SELECT `{status_col}`, COUNT(*) as cnt
                    FROM {self.database}.http
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                    GROUP BY `{status_col}`
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                details['status_codes'] = {str(row[0]): row[1] for row in cursor.fetchall() if row[0]}
                cursor.close()
            
            # Unique user agents
            if ua_col in columns:
                query = f"""
                    SELECT COUNT(DISTINCT `{ua_col}`)
                    FROM {self.database}.http
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                row = cursor.fetchone()
                details['unique_user_agents'] = row[0] if row else 0
                cursor.close()
                
        except HiveServer2Error:
            pass
        
        return details
    
    def _get_ssl_details(self, columns: List[str], ts_col: str,
                          start_time: datetime, end_time: datetime,
                          condition_sql: str) -> Dict[str, Any]:
        """Get TLS/SSL-specific aggregates."""
        details = {}
        version_col = self._ssl_cols.get('version', 'version')
        ja3_col = self._ssl_cols.get('ja3', 'ja3')
        sn_col = self._ssl_cols.get('server_name', 'server_name')
        
        try:
            # TLS versions
            if version_col in columns:
                query = f"""
                    SELECT `{version_col}`, COUNT(*) as cnt
                    FROM {self.database}.ssl
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                    GROUP BY `{version_col}`
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                details['versions'] = {row[0]: row[1] for row in cursor.fetchall() if row[0]}
                cursor.close()
            
            # Unique JA3
            if ja3_col in columns:
                query = f"""
                    SELECT COUNT(DISTINCT `{ja3_col}`)
                    FROM {self.database}.ssl
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                row = cursor.fetchone()
                details['unique_ja3'] = row[0] if row else 0
                cursor.close()
            
            # Unique server names
            if sn_col in columns:
                query = f"""
                    SELECT COUNT(DISTINCT `{sn_col}`)
                    FROM {self.database}.ssl
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                row = cursor.fetchone()
                details['unique_server_names'] = row[0] if row else 0
                cursor.close()
                
        except HiveServer2Error:
            pass
        
        return details
    
    def _get_smtp_details(self, columns: List[str], ts_col: str,
                           start_time: datetime, end_time: datetime,
                           condition_sql: str) -> Dict[str, Any]:
        """Get SMTP-specific aggregates."""
        details = {}
        mailfrom_col = self._smtp_cols.get('mailfrom', 'mailfrom')
        rcptto_col = self._smtp_cols.get('rcptto', 'rcptto')
        
        try:
            if mailfrom_col in columns:
                query = f"""
                    SELECT COUNT(DISTINCT `{mailfrom_col}`)
                    FROM {self.database}.smtp
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                row = cursor.fetchone()
                details['unique_senders'] = row[0] if row else 0
                cursor.close()
            
            if rcptto_col in columns:
                query = f"""
                    SELECT COUNT(DISTINCT `{rcptto_col}`)
                    FROM {self.database}.smtp
                    WHERE `{ts_col}` >= '{start_time.isoformat()}'
                      AND `{ts_col}` <= '{end_time.isoformat()}'
                      AND ({condition_sql})
                """
                cursor = self.connection.cursor()
                cursor.execute(query)
                row = cursor.fetchone()
                details['unique_recipients'] = row[0] if row else 0
                cursor.close()
                
        except HiveServer2Error:
            pass
        
        return details
    
    def _compute_peer_summary(self, aggregates: ZeekAggregates) -> None:
        """Compute peer entity summary with concentration metrics."""
        # Combine src and dst for peer analysis
        all_ips = {}
        for ip in aggregates.distinct_src_ips:
            all_ips[ip] = all_ips.get(ip, 0) + 1
        for ip in aggregates.distinct_dst_ips:
            all_ips[ip] = all_ips.get(ip, 0) + 1
        
        if not all_ips:
            return
        
        # Sort by count
        sorted_peers = sorted(all_ips.items(), key=lambda x: x[1], reverse=True)
        total = sum(all_ips.values())
        
        # Top peers
        aggregates.peer_entities = [
            {'ip': ip, 'count': cnt, 'country': 'Unknown'}
            for ip, cnt in sorted_peers[:10]
        ]
        
        # Concentration metrics
        if len(sorted_peers) >= 1:
            top1 = sorted_peers[0][1] / total if total > 0 else 0
            aggregates.peer_entities.append({'top1_share': round(top1, 4)})
        
        if len(sorted_peers) >= 3:
            top3 = sum(p[1] for p in sorted_peers[:3]) / total if total > 0 else 0
            aggregates.peer_entities.append({'top3_share': round(top3, 4)})
    
    def _get_protocol_for_table(self, table_name: str) -> str:
        """Map Zeek log table name to protocol name."""
        protocol_map = {
            'conn': 'TCP/UDP',
            'dns': 'DNS',
            'http': 'HTTP',
            'ssl': 'TLS/SSL',
            'smtp': 'SMTP',
            'ssh': 'SSH',
            'ftp': 'FTP',
            'rdp': 'RDP',
            'imap': 'IMAP',
            'pop3': 'POP3',
            'telnet': 'Telnet',
            'netflow': 'NetFlow',
            'files': 'File Transfer',
            'x509': 'X.509',
            'notice': 'Notice'
        }
        return protocol_map.get(table_name, table_name.upper())
