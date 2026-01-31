#!/bin/bash
# Run SOC_Intelligence Streamlit Dashboard

echo "SOC Intelligence Platform"
echo "=============================="
echo ""
echo "Starting Streamlit dashboard..."
echo ""

# Navigate to project root
cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run Streamlit
streamlit run src/app/main.py \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --browser.gatherUsageStats false \
    --theme.base "light" \
    --theme.primaryColor "#3498db"
