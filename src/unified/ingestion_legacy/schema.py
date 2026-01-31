
import pyarrow as pa

# Standard Network Event Schema (Arrow) - ECS Hybrid v1
NETWORK_EVENT_SCHEMA = pa.schema([
('@timestamp', pa.timestamp('us')),
('source.ip', pa.string()),
('source.port', pa.int32()),
('destination.ip', pa.string()),
('destination.port', pa.int32()),
('network.protocol', pa.string()),
('network.transport', pa.string()),
('network.bytes', pa.int64()),
('duration', pa.float64()),
('risk_score', pa.int32()),
('alert_id', pa.string()),
('alert.message', pa.string()),
('data.source', pa.string()),
('enrichment', pa.string()),
# One_Blink Forensic Extensions
('osi_stack', pa.string()),
('network.community_id', pa.string()),
('network.ttl', pa.int32()),
('tcp.flags', pa.string()),
('url.domain', pa.string()),
('dns.question.name', pa.string()),
('tls.client.server_name', pa.string()),
('user_agent.original', pa.string()),
('http.content_type', pa.string()),
# Expanded L3-L7 Deep Forensic Fields
('http.request.method', pa.string()),
('http.response.status_code', pa.int32()),
('dns.question.type', pa.string()),
('dns.answers', pa.string()),
('tls.handshake.ja3', pa.string()),
('tls.handshake.ciphersuite', pa.string()),
('icmp.type', pa.int32()),
('icmp.code', pa.int32()),
('tcp.seq', pa.int64()),
('tcp.ack', pa.int64()),
('tcp.window_size_value', pa.int32()),
('tls.record.version', pa.string()),
('icmp.ident', pa.int32()),
('tcp.options.timestamp.tsval', pa.int64()),
('dhcp.option.hostname', pa.string()),
('dhcp.option.dhcp_server_id', pa.string()),
('ssh.protocol', pa.string()),
('smb.cmd', pa.string()),
('ftp.request.command', pa.string())
])

# SQL DDL for Base Table
DDL_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
"@timestamp" TIMESTAMP,
"source.ip" VARCHAR,
"source.port" INTEGER,
"destination.ip" VARCHAR,
"destination.port" INTEGER,
"network.protocol" VARCHAR,
"network.transport" VARCHAR,
"network.bytes" BIGINT,
"duration" DOUBLE,
"risk_score" INTEGER,
"alert_id" VARCHAR,
"alert.message" VARCHAR,
"data.source" VARCHAR,
"enrichment" JSON,
"osi_stack" VARCHAR,
"network.community_id" VARCHAR,
"network.ttl" INTEGER,
"tcp.flags" VARCHAR,
"url.domain" VARCHAR,
"dns.question.name" VARCHAR,
"tls.client.server_name" VARCHAR,
"user_agent.original" VARCHAR,
"http.content_type" VARCHAR,
"http.request.method" VARCHAR,
"http.response.status_code" INTEGER,
"dns.question.type" VARCHAR,
"dns.answers" VARCHAR,
"tls.handshake.ja3" VARCHAR,
"tls.handshake.ciphersuite" VARCHAR,
"icmp.type" INTEGER,
"icmp.code" INTEGER,
"tcp.seq" BIGINT,
"tcp.ack" BIGINT,
"tcp.window_size_value" INTEGER,
"tls.record.version" VARCHAR,
"icmp.ident" INTEGER,
"tcp.options.timestamp.tsval" BIGINT,
"dhcp.option.hostname" VARCHAR,
"dhcp.option.dhcp_server_id" VARCHAR,
"ssh.protocol" VARCHAR,
"smb.cmd" VARCHAR,
"ftp.request.command" VARCHAR
);
"""

# MSSP Asset Mapping Table
DDL_ASSETS_TABLE = """
CREATE TABLE IF NOT EXISTS assets (
"ip_address" VARCHAR PRIMARY KEY,
"hostname" VARCHAR,
"asset_type" VARCHAR,
"importance" VARCHAR, -- e.g., 'Critical', 'High', 'Medium', 'Low'
"owner" VARCHAR,
"tenant_id" VARCHAR,
"last_seen" TIMESTAMP
);
"""

# Offline Reputation Table
DDL_REPUTATION_TABLE = """
CREATE TABLE IF NOT EXISTS reputation (
"indicator" VARCHAR PRIMARY KEY, -- IP or Domain
"reputation_score" INTEGER, -- 0-100 (100 is high risk)
"source" VARCHAR,
"threat_type" VARCHAR,
"last_updated" TIMESTAMP
);
"""

# Schema Mapping for Padding (Pandas Types)
SCHEMA_MAP = {
'@timestamp': 'datetime64[ns]',
'source.ip': 'str',
'source.port': 'Int32',
'destination.ip': 'str',
'destination.port': 'Int32',
'network.protocol': 'str',
'network.transport': 'str',
'network.bytes': 'int64',
'duration': 'float64',
'risk_score': 'int32',
'alert_id': 'str',
'alert.message': 'str',
'data.source': 'str',
'enrichment': 'str',
'osi_stack': 'str',
'network.community_id': 'str',
'network.ttl': 'Int32',
'tcp.flags': 'str',
'url.domain': 'str',
'dns.question.name': 'str',
'tls.client.server_name': 'str',
'user_agent.original': 'str',
'http.content_type': 'str',
'http.request.method': 'str',
'http.response.status_code': 'Int32',
'dns.question.type': 'str',
'dns.answers': 'str',
'tls.handshake.ja3': 'str',
'tls.handshake.ciphersuite': 'str',
'icmp.type': 'Int32',
'icmp.code': 'Int32',
'tcp.seq': 'int64',
'tcp.ack': 'int64',
'tcp.window_size_value': 'Int32',
'tls.record.version': 'str',
'icmp.ident': 'Int32',
'tcp.options.timestamp.tsval': 'int64',
'dhcp.option.hostname': 'str',
'dhcp.option.dhcp_server_id': 'str',
'ssh.protocol': 'str',
'smb.cmd': 'str',
'ftp.request.command': 'str'
}

# Export public interface
__all__ = ['NETWORK_EVENT_SCHEMA', 'DDL_EVENTS_TABLE', 'SCHEMA_MAP', 'DDL_ASSETS_TABLE', 'DDL_REPUTATION_TABLE']
