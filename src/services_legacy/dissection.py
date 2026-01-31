
import pyshark
import logging
import asyncio
import threading
from typing import List, Dict, Any
import nest_asyncio
import os
import concurrent.futures
import time

# Patch asyncio to allow nested event loops
nest_asyncio.apply()

logger = logging.getLogger(__name__)

# Global Singleton for Background Loop
_GLOBAL_LOOP = None
_GLOBAL_LOOP_THREAD = None
_LOOP_LOCK = threading.Lock()

def _start_background_loop():
    """Starts a new event loop in a daemon thread."""
    global _GLOBAL_LOOP
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _GLOBAL_LOOP = loop
        logger.info("Background asyncio loop started.")
        loop.run_forever()
    except Exception as e:
        logger.critical(f"Background loop crashed: {e}")

def _ensure_loop_running():
    """Ensures the global background loop is running."""
    global _GLOBAL_LOOP, _GLOBAL_LOOP_THREAD
    with _LOOP_LOCK:
        if _GLOBAL_LOOP is None or _GLOBAL_LOOP_THREAD is None or not _GLOBAL_LOOP_THREAD.is_alive():
            logger.info("Starting persistent background asyncio loop for DissectionService...")
            _GLOBAL_LOOP_THREAD = threading.Thread(target=_start_background_loop, daemon=True)
            _GLOBAL_LOOP_THREAD.start()

            # Wait briefly for loop to initialize
            retries = 0
            while _GLOBAL_LOOP is None and retries < 20: # Wait up to 2 seconds
                time.sleep(0.1)
                retries += 1

            if _GLOBAL_LOOP is None:
                logger.error("Failed to initialize background asyncio loop!")

class DissectionService:
    """
    Advanced Dissection Service using PyShark (TShark Python Wrapper).
    Run asynchronously in a background thread to prevent Streamlit event loop conflicts.
    """

    def __init__(self):
        _ensure_loop_running()

    def get_packet_details(self, pcap_path: str, packet_count: int = 10) -> List[Dict[str, Any]]:
        """Synchronous wrapper for async packet extraction."""
        if _GLOBAL_LOOP is None: return [] # Safety check
        future = asyncio.run_coroutine_threadsafe(
            self._get_packet_details_async(pcap_path, packet_count), _GLOBAL_LOOP
        )
        return future.result()

    async def _get_packet_details_async(self, pcap_path: str, packet_count: int = 10) -> List[Dict[str, Any]]:
        """Internal async implementation."""
        try:
            pcap_path = os.path.expanduser(pcap_path)
            cap = pyshark.FileCapture(pcap_path)
            packets = []

            for i, pkt in enumerate(cap):
                if i >= packet_count: break
                packet_info = {
                    "number": pkt.number,
                    "layers": [layer.layer_name for layer in pkt.layers],
                    "@timestamp": pkt.sniff_time.isoformat(),
                    "network.bytes": pkt.length,
                }
                if 'IP' in pkt:
                    packet_info['source.ip'] = pkt.ip.src
                    packet_info['destination.ip'] = pkt.ip.dst
                packets.append(packet_info)

            cap.close()
            return packets
        except Exception as e:
            logger.error(f"PyShark dissection failed: {e}", exc_info=True)
            return []

    def get_full_protocol_tree(self, pcap_path: str, packet_number: int) -> Dict[str, Any]:
        """Synchronous wrapper for full tree extraction."""
        if _GLOBAL_LOOP is None: return {"error": "Background loop not active"}
        future = asyncio.run_coroutine_threadsafe(
            self._get_full_protocol_tree_async(pcap_path, packet_number), _GLOBAL_LOOP
        )
        return future.result()

    async def _get_full_protocol_tree_async(self, pcap_path: str, packet_number: int) -> Dict[str, Any]:
        """Internal async implementation for deep scan."""
        try:
            pcap_path = os.path.expanduser(pcap_path)
            # Re-read specific packet
            cap = pyshark.FileCapture(pcap_path, display_filter=f"frame.number == {packet_number}")
            pkt = next(iter(cap))

            full_tree = {}
            for layer in pkt.layers:
                layer_data = {}
                for field in layer.field_names:
                    try:
                        layer_data[field] = getattr(layer, field)
                    except:
                        pass
                full_tree[layer.layer_name] = layer_data

            cap.close()
            return full_tree
        except Exception as e:
            logger.error(f"Full protocol tree extraction failed: {e}", exc_info=True)
            return {"error": str(e)}

    def get_forensic_indicators(self, pcap_path: str, packet_number: int) -> Dict[str, Any]:
        """Extracts high-value forensic indicators."""
        if _GLOBAL_LOOP is None: return {"error": "Background loop not active"}
        future = asyncio.run_coroutine_threadsafe(
            self._get_forensic_indicators_async(pcap_path, packet_number), _GLOBAL_LOOP
        )
        return future.result()

    async def _get_forensic_indicators_async(self, pcap_path: str, packet_number: int) -> Dict[str, Any]:
        """Async wrapper for forensic indicators."""
        import numpy as np
        import binascii
        from pyshark.capture.capture import TSharkCrashException

        try:
            pcap_path = os.path.expanduser(pcap_path)
            cap = pyshark.FileCapture(pcap_path, display_filter=f"frame.number == {packet_number}")

            # Defensive Iterator to catch crash on 'next()'
            try:
                pkt = next(iter(cap))
            except TSharkCrashException as e:
                logger.warning(f"TShark crashed on packet #{packet_number} (Likely Malformed): {e}")
                cap.close()
                return {"error": "Packet content malformed (TShark crash)"}
            except StopIteration:
                cap.close()
                return {"error": "Packet not found"}

            indicators = {}

            # 1. Entropy Calculation
            if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload'):
                try:
                    raw_payload = pkt.tcp.payload.replace(':', '')
                    data = binascii.unhexlify(raw_payload)
                    if data:
                        probs = [float(data.count(bytes([c]))) / len(data) for c in set(data)]
                        entropy = -sum(p * np.log2(p) for p in probs)
                        indicators['payload_entropy'] = round(entropy, 4)
                        indicators['payload_hex_preview'] = raw_payload[:64] + "..."
                except Exception:
                    pass # Fail silently on entropy if payload is weird

            # 2. SSL/TLS Details
            if 'TLS' in pkt:
                indicators['tls_version'] = getattr(pkt.tls, 'record_version', 'Unknown')
                indicators['tls_cipher'] = getattr(pkt.tls, 'handshake_ciphersuite', 'Unknown')
                if hasattr(pkt.tls, 'handshake_extensions_server_name'):
                    indicators['tls_sni'] = pkt.tls.handshake_extensions_server_name

            # 3. HTTP Details
            if 'HTTP' in pkt:
                indicators['http_method'] = getattr(pkt.http, 'request_method', 'N/A')
                indicators['http_host'] = getattr(pkt.http, 'host', 'N/A')
                indicators['http_uri'] = getattr(pkt.http, 'request_uri', 'N/A')
                indicators['http_user_agent'] = getattr(pkt.http, 'user_agent', 'N/A')

            cap.close()
            return indicators

        except Exception as e:
            # General fallback
            logger.error(f"Forensic indicators extraction failed: {e}")
            return {"error": str(e)}

    def get_filtered_packets(self, pcap_path: str, display_filter: str, count: int = 5) -> List[Dict[str, Any]]:
        """Synchronous wrapper for filtered scan."""
        if _GLOBAL_LOOP is None: return []
        future = asyncio.run_coroutine_threadsafe(
            self._get_filtered_packets_async(pcap_path, display_filter, count), _GLOBAL_LOOP
        )
        return future.result()

    async def _get_filtered_packets_async(self, pcap_path: str, display_filter: str, count: int = 5) -> List[Dict[str, Any]]:
        """Internal async implementation."""
        results = []
        from pyshark.capture.capture import TSharkCrashException
        try:
            pcap_path = os.path.expanduser(pcap_path)
            cap = pyshark.FileCapture(pcap_path, display_filter=display_filter)

            try:
                for i, pkt in enumerate(cap):
                    if i >= count: break
                    packet_info = {
                        "number": pkt.number,
                        "layers": [layer.layer_name for layer in pkt.layers],
                        "@timestamp": pkt.sniff_time.isoformat(),
                        "length": pkt.length
                    }
                    if 'IP' in pkt:
                        packet_info['src'] = pkt.ip.src
                        packet_info['dst'] = pkt.ip.dst
                    results.append(packet_info)
            except TSharkCrashException as e:
                logger.warning(f"TShark crashed during filtered dissection (display_filter='{display_filter}'): {e}")
                pass

            cap.close()
            return results
        except Exception as e:
            logger.error(f"Filtered dissection failed: {e}")
            return [{"error": str(e)}]
