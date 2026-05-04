from flask import Flask, render_template, jsonify 
import pandas as pd, os, subprocess 
  
app = Flask(__name__) 
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data') 
  
def load_data(): 
    try: 
        df = pd.read_csv(os.path.join(DATA_DIR, 'final_report.csv')) 
        return df[df['ip'] != 'synthetic'] 
    except FileNotFoundError: 
        try: 
            df = pd.read_csv(os.path.join(DATA_DIR, 'ml_results.csv')) 
            df['llm_explanation'] = 'LLM stage not yet run.' 
            return df[df['ip'] != 'synthetic'] 
        except: 
            return pd.DataFrame() 
  
@app.route('/') 
def index(): 
    df = load_data() 
    stats = {} 
    if not df.empty: 
        stats = { 
            'total_hosts': df['ip'].nunique(), 
            'high': len(df[df['ml_prediction']=='High']), 
            'medium': len(df[df['ml_prediction']=='Medium']), 
            'low': len(df[df['ml_prediction']=='Low']), 
            'total_ports': int(df['open_port_count'].sum())
               } 
    return render_template('index.html', stats=stats) 
  
@app.route('/results') 
def results(): 
    df = load_data() 
    data = df.to_dict('records') if not df.empty else [] 
    return render_template('results.html', data=data) 
  
@app.route('/report') 
def report(): 
    df = load_data() 
    data = df.to_dict('records') if not df.empty else [] 
    return render_template('report.html', data=data) 
  
@app.route('/api/results') 
def api_results(): 
    df = load_data() 
    return jsonify(df.to_dict('records') if not df.empty else []) 
  
@app.route('/run-pipeline', methods=['POST']) 
def run_pipeline(): 
    try: 
        subprocess.Popen(['bash', 'pipeline/run_pipeline.sh']) 
        return jsonify({'status': 'Pipeline started in background'}) 
    except Exception as e: 
        return jsonify({'status': f'Error: {e}'}), 500 
  
if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=5000, debug=True) 