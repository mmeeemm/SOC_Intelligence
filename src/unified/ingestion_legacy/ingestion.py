
import logging
import subprocess
import pandas as pd
import polars as pl
from io import StringIO
from pathlib import Path
from src.data.db_client import db
from src.data.schema import DDL_EVENTS_TABLE
from src.data.discovery import SemanticMapper

from src.utils.forensics import generate_community_id

logger = logging.getLogger(__name__)

class IngestionEngine:
    """
    Handles data loading from various sources into DuckDB.
    Supports: CSV, JSON, Parquet, PCAP (via tshark).
    """

    def __init__(self):
        # Ensure base table exists with correct schema
        try:
            db.execute(DDL_EVENTS_TABLE)
        except Exception as e:
            logger.error(f"Failed to ensure events table exists: {e}")

    def load_file(self, file_path: str, table_name="events", append=False, enrich=True) -> bool:
        """
        Load a file into DuckDB.
        Auto-detects format.
        """
        path = Path(file_path)
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return False

        ext = path.suffix.lower()

        try:
            success = False
            if ext == '.csv':
                success = self._load_csv(path, table_name, append=append)
            elif ext == '.parquet':
                success = self._load_parquet(path, table_name, append=append)
            elif ext in ['.json', '.ndjson']:
                success = self._load_json(path, table_name, append=append)
            elif ext in ['.pcap', '.pcapng']:
                success = self._load_pcap(path, table_name, append=append, enrich=enrich)
            elif ext == '.log':
                # Check if it's a Zeek log
                with open(path, 'r') as f:
                    first_line = f.readline()
                    if first_line.startswith("#separator") or first_line.startswith('{"'):
                        success = self._load_zeek(path, table_name, append=append)
                    else:
                        success = self._load_csv(path, table_name, append=append)
            else:
                logger.warning(f"Unsupported file format: {ext}")
                return False

            if success:
                logger.info(f"Successfully loaded {file_path} into {table_name} (append={append})")
            return success

        except Exception as e:
            logger.error(f"Ingestion failed for {file_path}: {e}", exc_info=True)
            return False

    def load_dataframe(self, df: pd.DataFrame, table_name="events", append=True) -> bool:
        """Standardized method for loading a DataFrame into DuckDB with schema alignment."""
        if df is None or df.empty:
            return False

        try:
            df_aligned = self._ensure_schema_alignment(df)

            # Register the dataframe as a temporary view
            try:
                db.conn.unregister('df_view')
            except: pass
            db.conn.register('df_view', df_aligned)

            # Ensure Schema Consistency
            if not append:
                db.execute(f"DROP TABLE IF EXISTS {table_name}")

            # Create table if not exists using strict schema
            ddl = DDL_EVENTS_TABLE.replace("TABLE IF NOT EXISTS events", f"TABLE IF NOT EXISTS {table_name}")
            db.execute(ddl)

            # Insert data using EXPLICIT Column List
            cols = ", ".join([f'"{c}"' for c in df_aligned.columns])
            db.execute(f"INSERT INTO {table_name} ({cols}) SELECT * FROM df_view")

            # Unregister to clean up
            db.conn.unregister('df_view')
            logger.info(f"Successfully loaded {len(df_aligned)} records into {table_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to load dataframe into {table_name}: {e}")
            return False

    def _ensure_schema_alignment(self, df: pd.DataFrame) -> pd.DataFrame:
        """Pads dataframe with missing columns from the master schema"""
        from src.data.schema import SCHEMA_MAP
        for col in SCHEMA_MAP.keys():
            if col not in df.columns:
                df[col] = None

        # Standardize baseline risk
        if 'risk_score' in df.columns:
            df['risk_score'] = df['risk_score'].fillna(10)
        else:
            df['risk_score'] = 10

        # Reorder to match master schema
        return df[list(SCHEMA_MAP.keys())]

    def _load_csv(self, path: Path, table_name: str, append=False):
        """Load CSV with semantic header discovery"""
        df = pd.read_csv(path)
        df_mapped = SemanticMapper.discover_and_map(df)

        if '@timestamp' not in df_mapped.columns:
            df_mapped['@timestamp'] = pd.Timestamp.now()
        if 'risk_score' not in df_mapped.columns:
            df_mapped['risk_score'] = 0
        df_mapped['data.source'] = 'csv_mystery'

        df_aligned = self._ensure_schema_alignment(df_mapped)
        return self.load_dataframe(df_aligned, table_name, append=append)

    def _load_parquet(self, path: Path, table_name: str, append=False):
        if not append:
            sql = f"CREATE OR REPLACE TABLE {table_name} AS SELECT * FROM read_parquet('{path}');"
        else:
            sql = f"INSERT INTO {table_name} SELECT * FROM read_parquet('{path}');"
        db.execute(sql)
        return True

    def _load_json(self, path: Path, table_name: str, append=False):
        """Load JSON with semantic header discovery"""
        try:
            df = pd.read_json(path)
        except:
            df = pd.read_json(path, lines=True)

        df_mapped = SemanticMapper.discover_and_map(df)
        if '@timestamp' not in df_mapped.columns:
            df_mapped['@timestamp'] = pd.Timestamp.now()
        df_mapped['data.source'] = 'json_mystery'

        df_aligned = self._ensure_schema_alignment(df_mapped)
        return self.load_dataframe(df_aligned, table_name, append=append)

    def _load_pcap(self, path: Path, table_name: str, append=False, enrich=True):
        """Orchestrates Full Forensic Ingestion (Packet + Session + Alert)."""
        success = True
        logger.info(f"Analyzing PCAP: {path.name}...")

        # TShark Command for Layer 1-7 Extraction
        cmd_csv = [
            "tshark", "-r", str(path),
            "-n", "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src", "-e", "ipv6.src", "-e", "tcp.srcport", "-e", "udp.srcport",
            "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.dstport", "-e", "udp.dstport",
            "-e", "ip.ttl", "-e", "ipv6.hlim",
            "-e", "tcp.flags.str", "-e", "frame.len",
            "-e", "_ws.col.Protocol", "-e", "frame.protocols",
            "-e", "http.host", "-e", "http.user_agent", "-e", "http.content_type",
            "-e", "http.request.method", "-e", "http.response.code",
            "-e", "dns.qry.name", "-e", "dns.qry.type", "-e", "dns.resp.name",
            "-e", "tls.handshake.extensions_server_name", "-e", "tls.handshake.ja3",
            "-e", "tls.handshake.ciphersuite", "-e", "tls.record.version",
            "-e", "icmp.type", "-e", "icmp.code", "-e", "icmp.ident",
            "-e", "tcp.seq", "-e", "tcp.ack", "-e", "tcp.window_size_value",
            "-e", "_ws.col.info", "-e", "dhcp.option.hostname",
            "-e", "ssh.protocol", "-e", "smb.cmd", "-e", "ftp.request.command",
            "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"
        ]

        temp_csv = path.with_suffix('.temp.csv')
        try:
            with open(temp_csv, 'w') as f:
                subprocess.run(cmd_csv, stdout=f, check=True)

            df_pl = pl.read_csv(temp_csv, infer_schema_length=0, null_values=["", "nan", "None"])
            
            # Map columns and enrich with Polars for speed
            required_cols = [
                'frame.time_epoch', 'ip.src', 'ipv6.src', 'tcp.srcport', 'udp.srcport',
                'ip.dst', 'ipv6.dst', 'tcp.dstport', 'udp.dstport', 'ip.ttl', 'ipv6.hlim',
                'tcp.flags.str', 'frame.len', '_ws.col.Protocol', 'frame.protocols',
                'http.host', 'http.user_agent', 'http.content_type', 'http.request.method',
                'http.response.code', 'dns.qry.name', 'dns.qry.type', 'dns.resp.name', 
                'tls.handshake.extensions_server_name', 'tls.handshake.ja3', 'tls.handshake.ciphersuite',
                'tls.record.version', 'icmp.type', 'icmp.code', 'icmp.ident', 'tcp.seq', 'tcp.ack',
                'tcp.window_size_value', '_ws.col.info', 'dhcp.option.hostname', 'ssh.protocol',
                'smb.cmd', 'ftp.request.command'
            ]
            for col in required_cols:
                if col not in df_pl.columns:
                    df_pl = df_pl.with_columns(pl.lit(None, pl.Utf8).alias(col))

            protocol_expr = (
                pl.when(pl.col('_ws.col.Protocol').is_not_null() & (pl.col('_ws.col.Protocol').str.to_uppercase() != "DATA"))
                .then(pl.col('_ws.col.Protocol').str.to_uppercase().str.replace_all(r"[\[\]]", ""))
                .when(pl.col('frame.protocols').is_not_null())
                .then(pl.col('frame.protocols').str.split(":").list.tail(1).list.get(0).str.to_uppercase())
                .otherwise(pl.lit("TCP"))
            )

            df_mapped_pl = df_pl.select([
                pl.col('frame.time_epoch').cast(pl.Float64).cast(pl.Datetime('us')).alias('@timestamp'),
                pl.coalesce(['ip.src', 'ipv6.src', pl.lit('unknown')]).alias('source.ip'),
                pl.coalesce([pl.col('tcp.srcport').cast(pl.Int32, strict=False), pl.col('udp.srcport').cast(pl.Int32, strict=False), pl.lit(0)]).alias('source.port'),
                pl.coalesce(['ip.dst', 'ipv6.dst', pl.lit('unknown')]).alias('destination.ip'),
                pl.coalesce([pl.col('tcp.dstport').cast(pl.Int32, strict=False), pl.col('udp.dstport').cast(pl.Int32, strict=False), pl.lit(0)]).alias('destination.port'),
                pl.coalesce([pl.col('ip.ttl').cast(pl.Int32, strict=False), pl.col('ipv6.hlim').cast(pl.Int32, strict=False), pl.lit(0)]).alias('network.ttl'),
                protocol_expr.alias('network.protocol'),
                pl.when(pl.col('tcp.srcport').is_not_null()).then(pl.lit('tcp')).otherwise(pl.lit('udp')).alias('network.transport'),
                pl.col('frame.len').cast(pl.Int64, strict=False).fill_null(0).alias('network.bytes'),
                pl.lit(0.0).alias('duration'),
                pl.lit(10).alias('risk_score'),
                pl.lit('tshark').alias('data.source'),
                pl.col('frame.protocols').alias('osi_stack'),
                pl.col('tcp.flags.str').alias('tcp.flags'),
                pl.coalesce(['http.host', 'tls.handshake.extensions_server_name']).alias('url.domain'),
                pl.col('dns.qry.name').alias('dns.question.name'),
                pl.col('tls.handshake.extensions_server_name').alias('tls.client.server_name'),
                pl.col('http.user_agent').alias('user_agent.original'),
                pl.col('http.content_type').alias('http.content_type'),
                pl.col('http.request.method').alias('http.request.method'),
                pl.col('http.response.code').cast(pl.Int32, strict=False).fill_null(0).alias('http.response.status_code'),
                pl.col('dns.qry.type').alias('dns.question.type'),
                pl.col('dns.resp.name').alias('dns.answers'),
                pl.col('tls.handshake.ja3').alias('tls.handshake.ja3'),
                pl.col('tls.handshake.ciphersuite').alias('tls.handshake.ciphersuite'),
                pl.col('icmp.type').cast(pl.Int32, strict=False).fill_null(-1).alias('icmp.type'),
                pl.col('icmp.code').cast(pl.Int32, strict=False).fill_null(-1).alias('icmp.code'),
                pl.col('tcp.seq').cast(pl.Int64, strict=False).fill_null(0).alias('tcp.seq'),
                pl.col('tcp.ack').cast(pl.Int64, strict=False).fill_null(0).alias('tcp.ack'),
                pl.col('tcp.window_size_value').cast(pl.Int32, strict=False).fill_null(0).alias('tcp.window_size_value'),
                pl.col('tls.record.version').alias('tls.record.version'),
                pl.col('icmp.ident').cast(pl.Int32, strict=False).fill_null(0).alias('icmp.ident'),
                pl.col('dhcp.option.hostname').alias('dhcp.option.hostname'),
                pl.col('ssh.protocol').alias('ssh.protocol'),
                pl.col('smb.cmd').alias('smb.cmd'),
                pl.col('ftp.request.command').alias('ftp.request.command')
            ])

            df = df_mapped_pl.to_pandas()
            df['network.community_id'] = df.apply(
                lambda r: generate_community_id(r['source.ip'], r['destination.ip'], r['source.port'], r['destination.port'], r['network.transport']),
                axis=1
            )
            success = self.load_dataframe(df, table_name, append=append)

            if enrich:
                # 2. Zeek (Session Layer)
                logger.info(f"Enriching with Zeek for {path.name}...")
                ze_out = path.parent / f"zeek_out_{path.stem}"
                ze_out.mkdir(exist_ok=True)
                subprocess.run(["zeek", "-C", "-r", str(path), f"Log::default_logdir={ze_out}"], check=False)
                for log in ze_out.glob("*.log"):
                    self._load_zeek(log, table_name, append=True)
                import shutil
                shutil.rmtree(ze_out)

                # 3. Snort (Alert Layer)
                logger.info(f"Enriching with Snort for {path.name}...")
                from src.services.snort import SnortService
                snort = SnortService()
                if snort.is_available():
                    alerts_df = snort.run_on_pcap(str(path))
                    if not alerts_df.empty:
                        self.load_dataframe(alerts_df, table_name, append=True)

        except Exception as e:
            logger.error(f"In-depth PCAP ingestion failed: {e}")
            success = False
        finally:
            if temp_csv.exists(): temp_csv.unlink()

        return success

    def _load_zeek(self, path: Path, table_name: str, append=False):
        """Parses Zeek logs (JSON/TSV) and loads into DuckDB."""
        try:
            with open(path, 'r') as f:
                first_line = f.readline()
                if first_line.startswith("#separator"):
                    # TSV parsing simplified for brevity
                    df = pd.read_csv(path, sep='\t', comment='#', names=['ts', 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes'])
                    df_pl = pl.from_pandas(df)
                else:
                    df_pl = pl.read_ndjson(path)

            # Map to ECS
            rename_map = {'id.orig_h': 'src_ip', 'id.orig_p': 'src_port', 'id.resp_h': 'dst_ip', 'id.resp_p': 'dst_port', 'proto': 'protocol', 'orig_bytes': 'bytes_out', 'resp_bytes': 'bytes_in'}
            current_rename = {k: v for k, v in rename_map.items() if k in df_pl.columns}
            if current_rename: df_pl = df_pl.rename(current_rename)

            # Select and cast
            pdf = df_pl.to_pandas()
            # Minimal mapping for Zeek logs in this context
            pdf['@timestamp'] = pd.to_datetime(pdf['ts'], unit='s')
            pdf['source.ip'] = pdf['src_ip']
            pdf['source.port'] = pdf['src_port']
            pdf['destination.ip'] = pdf['dst_ip']
            pdf['destination.port'] = pdf['dst_port']
            pdf['network.protocol'] = pdf.get('service', 'ZEEK').str.upper()
            pdf['network.transport'] = pdf.get('protocol', 'TCP').str.lower()
            pdf['network.bytes'] = pdf.get('bytes_out', 0).fillna(0) + pdf.get('bytes_in', 0).fillna(0)
            pdf['data.source'] = 'zeek'
            pdf['risk_score'] = 10

            pdf_aligned = self._ensure_schema_alignment(pdf)
            return self.load_dataframe(pdf_aligned, table_name, append=append)

        except Exception as e:
            logger.error(f"Zeek ingestion failed: {e}")
            return False
