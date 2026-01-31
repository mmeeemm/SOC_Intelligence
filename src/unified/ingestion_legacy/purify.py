import logging
from src.data.db_client import db

logger = logging.getLogger(__name__)

class DataFusionService:
    """
    Performs 'Forensic Purification' by merging records from multiple tools
    (TShark, Zeek, Snort) into a single unified sighting.
    """

    PURIFY_SQL = f"""
    CREATE OR REPLACE TABLE purified_events AS
    SELECT
    "network.community_id",
    MIN("@timestamp") as "@timestamp",
    ANY_VALUE("source.ip") as "source.ip",
    ANY_VALUE("source.port") as "source.port",
    ANY_VALUE("destination.ip") as "destination.ip",
    ANY_VALUE("destination.port") as "destination.port",
    ANY_VALUE("network.transport") as "network.transport",

    -- Meta-data Fusion (Prioritize Zeek protocols)
    COALESCE(
    MAX(CASE WHEN "data.source" = 'zeek' AND "network.protocol" != '-' THEN "network.protocol" END),
    MAX(CASE WHEN "data.source" = 'tshark' THEN "network.protocol" END),
    'unknown'
    ) as "network.protocol",

    -- Volume Fusion (Prioritize Zeek Session Totals, else SUM TShark Packets)
    COALESCE(
    MAX(CASE WHEN "data.source" = 'zeek' THEN "network.bytes" END),
    SUM(CASE WHEN "data.source" = 'tshark' THEN "network.bytes" END),
    MAX("network.bytes")
    ) as "network.bytes",

    -- Forensic Insights (Overdrive: Carry over high-fidelity fields)
    MAX("risk_score") as "risk_score",
    STRING_AGG(DISTINCT "alert_id", ', ') as "alert_id",
    MAX("tls.handshake.ja3") as "tls.handshake.ja3",
    MAX("tls.client.server_name") as "tls.client.server_name",
    MAX("dns.question.name") as "dns.question.name",
    MAX("user_agent.original") as "user_agent.original",

    -- Fault-Tolerant TCP Analysis (Avoid Binder Errors if columns missing)
    MAX(CASE WHEN columns_exists('tcp.analysis.initial_rtt') THEN "tcp.analysis.initial_rtt" ELSE NULL END) as "tcp.analysis.initial_rtt",
    MAX(CASE WHEN columns_exists('tcp.analysis.retransmission') THEN "tcp.analysis.retransmission" ELSE NULL END) as "tcp.analysis.retransmission",

    ANY_VALUE("_ws.col.info") as "summary_info",

    COALESCE(
    MAX(CASE WHEN "data.source" = 'tshark' THEN "osi_stack" END),
    MAX("osi_stack")
    ) as "osi_stack",

    -- Phase 16: MITRE ATT&CK Mapping (Simplified)
    COALESCE(
    MAX(CASE 
        WHEN "alert.message" ILIKE '%scan%' OR "alert.message" ILIKE '%nmap%' THEN 'Discovery (T1046)'
        WHEN "alert.message" ILIKE '%c2%' OR "alert.message" ILIKE '%beacon%' THEN 'Command and Control (T1071)'
        WHEN "alert.message" ILIKE '%exploit%' OR "alert.message" ILIKE '%cve-%' THEN 'Execution (T1203)'
        WHEN "alert.message" ILIKE '%brute%force%' THEN 'Credential Access (T1110)'
        WHEN "alert.message" IS NOT NULL THEN 'General/Unknown'
        ELSE NULL
    END),
    'None / Benign'
    ) as "mitre_attack",

    -- Traceability
    STRING_AGG(DISTINCT "data.source", ', ') as "fused_sources"

    FROM events
    WHERE "network.community_id" IS NOT NULL AND "network.community_id" != 'none'
    GROUP BY "network.community_id";
    """

    @classmethod
    def purify_database(cls):
        """Execute the purification logic and swap tables if needed."""
        logger.info(" Starting Forensic Data Purification...")
        try:
            db.execute(cls.PURIFY_SQL)

            # Create Performance Indexes
            logger.info(" Optimizing database with forensic indexes...")
            db.execute('CREATE INDEX IF NOT EXISTS idx_comm_id ON purified_events ("network.community_id");')
            db.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON purified_events ("source.ip");')
            db.execute('CREATE INDEX IF NOT EXISTS idx_dst_ip ON purified_events ("destination.ip");')

            # Get stats
            stats = db.query("SELECT count(*) as c FROM purified_events")
            count = stats.iloc[0]['c'] if not stats.empty else 0

            logger.info(f" Purification Complete. Fused into {count} unique sightings.")
            return True
        except Exception as e:
            logger.error(f" Purification Failed: {e}")
            return False

    @classmethod
    def export_to_toon(cls, limit: int = None) -> str:
        """
        Export purified_events to TOON format with correlation.
        
        Args:
            limit: Optional limit on number of records to export
        
        Returns:
            Complete TOON output with CORR_GROUPs
        """
        from src.services.toon_transformer import toon_transformer
        from src.services.correlation_engine import correlation_engine
        from src.services.toon_validator import toon_validator
        
        logger.info(" Exporting purified_events to TOON format...")
        
        try:
            # Query purified events
            query = "SELECT * FROM purified_events"
            if limit:
                query += f" LIMIT {limit}"
            
            df = db.query(query)
            
            if df.empty:
                logger.warning("No purified events to export")
                return ""
            
            logger.info(f" Transforming {len(df)} records to TOON...")
            
            # Transform to TOON blocks
            toon_blocks = []
            for _, row in df.iterrows():
                toon_block = toon_transformer.from_duckdb(row)
                if toon_block:
                    toon_blocks.append(toon_block)
            
            logger.info(f" Transformed {len(toon_blocks)} records to TOON")
            
            # Correlate into CORR_GROUPs
            logger.info(" Correlating TOON blocks into CORR_GROUPs...")
            corr_groups = correlation_engine.correlate(toon_blocks)
            logger.info(f" Created {len(corr_groups)} CORR_GROUPs")
            
            # Validate
            logger.info(" Validating TOON CORR_GROUPs...")
            validation_result = toon_validator.validate(corr_groups)
            
            if validation_result.status == 'INVALID':
                logger.error(f" TOON validation failed: {validation_result.violations}")
                return str(validation_result)
            
            logger.info(f" ✓ TOON validation passed ({len(corr_groups)} groups)")
            
            # Convert to TOON output
            toon_output = validation_result.summary + "\n\n" if validation_result.summary else ""
            
            for group in corr_groups:
                toon_output += group.to_toon() + "\n\n"
            
            # Stats
            logger.info(f" TOON Export Stats:")
            logger.info(f"   - Transformation: {toon_transformer.get_stats()}")
            logger.info(f"   - Correlation: {correlation_engine.get_stats()}")
            
            return toon_output.strip()
            
        except Exception as e:
            logger.error(f" TOON export failed: {e}", exc_info=True)
            return f"ERROR: TOON export failed - {e}"

    @classmethod
    def generate_v6_report(cls, limit: int = None, reference_context: str = None) -> str:
        """
        Generate complete TOON Pipeline V6 enterprise report.
        
        This is the end-to-end pipeline:
        1. Export purified_events to TOON
        2. Correlate into CORR_GROUPs
        3. Validate
        4. Generate 18-section enterprise report
        
        Args:
            limit: Optional limit on records
            reference_context: Optional policy/baseline overrides
        
        Returns:
            Complete enterprise security report
        """
        from src.services.llm import llm
        
        logger.info("═══ TOON Pipeline V6: Full Execution ═══")
        
        # Step 1-3: Export, correlate, validate
        toon_output = cls.export_to_toon(limit=limit)
        
        if not toon_output or toon_output.startswith("ERROR") or toon_output.startswith("INVALID"):
            logger.error("TOON pipeline failed at transformation/validation stage")
            return toon_output
        
        logger.info(" TOON pipeline stages 1-3 complete (Transform → Correlate → Validate)")
        
        # Step 4: Generate enterprise report
        logger.info(" Generating 18-section enterprise report...")
        report = llm.generate_enterprise_report_v6(toon_output, reference_context)
        
        logger.info("═══ TOON Pipeline V6: Complete ═══")
        return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    DataFusionService.purify_database()
