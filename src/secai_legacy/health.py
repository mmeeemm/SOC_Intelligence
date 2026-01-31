"""
SecAI Reporter - Health Check Tool

Verifies database connectivity, environment variables, and library versions.
Essential for troubleshooting in air-gapped environments.
"""

import os
import sys
import logging
import importlib
from pathlib import Path
import yaml

def check_library(name):
    try:
        module = importlib.import_module(name)
        version = getattr(module, '__version__', 'unknown')
        print(f"✅ {name:15} | Version: {version}")
        return True
    except ImportError:
        print(f"❌ {name:15} | NOT FOUND")
        return False

def run_health_check(config_path=None):
    print("=" * 50)
    print("🔍 SecAI Reporter - Readiness Health Check")
    print("=" * 50)
    
    # 1. Environment & Python
    print("\n[1] Runtime Environment")
    print(f"Python Version: {sys.version.split()[0]}")
    print(f"OS: {sys.platform}")
    print(f"Current PID: {os.getpid()}")
    
    # 2. Key Libraries
    print("\n[2] Core Libraries")
    libs = [
        "django", "psycopg2", "impala", "pandas", 
        "torch", "transformers", "pydantic", "jsonschema"
    ]
    for lib in libs:
        check_library(lib)
        
    # 3. Configuration & Paths
    print("\n[3] Configuration & Paths")
    if not config_path:
        project_root = Path(__file__).parent.parent.parent
        config_path = project_root / "config" / "config.yaml"
    
    if os.path.exists(config_path):
        print(f"✅ Config File   | {config_path}")
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            print("✅ Config Parsing| OK")
        except Exception as e:
            print(f"❌ Config Parsing| FAILED: {e}")
            config = None
    else:
        print(f"❌ Config File   | NOT FOUND at {config_path}")
        config = None
        
    # 4. CPU / AI Resources
    print("\n[4] AI/CPU Resources")
    try:
        import torch
        print(f"Torch CPU Build: {'Yes' if not torch.cuda.is_available() else 'No (GPU active)'}")
        print(f"CPU Threads:     {torch.get_num_threads()}")
        
        if config and 'llm' in config:
            m_path = config['llm'].get('model_path')
            if m_path and os.path.exists(m_path):
                print(f"✅ LLM Model     | Found at {m_path}")
            else:
                print(f"⚠️  LLM Model     | Not found at path: {m_path}")
    except:
        print("❌ Torch Resources check failed")

    # 5. Connectors (Dry Run)
    print("\n[5] Database Connectors (Import Test)")
    try:
        from secai_reporter.connectors import PostgresDjangoConnector, ImpalaConnector
        print("✅ Connectors    | Loaded successfully")
    except Exception as e:
        print(f"❌ Connectors    | Load failed: {e}")

    print("\n" + "=" * 50)
    print("Health check complete.")
    print("=" * 50)

if __name__ == "__main__":
    run_health_check()
