#!/bin/bash 
set -e   # Stop on any error 
  
export OPENAI_API_KEY="your-api-key-here"


cd "$(dirname "$0")/.." 
  
echo "" 
echo "======================================" 
echo " Stage 1: Network Scan (Nmap)" 
echo "======================================" 
sudo bash scanner/scan.sh 
echo "" 
echo "======================================" 
echo " Stage 2: Feature Extraction" 
echo "======================================" 
python3 scanner/parse_nmap.py 
  
echo "" 
echo "======================================" 
echo " Stage 3: Label Dataset" 
echo "======================================" 
python3 scanner/label_dataset.py 
  
echo "" 
echo "======================================" 
echo " Stage 4: Train ML Models" 
echo "======================================" 
python3 ml/train_model.py 
  
echo "" 
echo "======================================" 
echo " Stage 5: LLM Explanations" 
echo "======================================" 
python3 llm/llm_explain.py 
  
echo "" 
echo "[✓] Pipeline complete! Start the dashboard with:" 
echo "    python3 web/app.py" 