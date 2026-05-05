from flask import Flask, render_template, jsonify, request, send_file
import pandas as pd, os, subprocess, io
from openai import OpenAI

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
    rows = []
    if not df.empty:
        stats = {
            'total_hosts': df['ip'].nunique(),
            'high': len(df[df['ml_prediction']=='High']),
            'medium': len(df[df['ml_prediction']=='Medium']),
            'low': len(df[df['ml_prediction']=='Low']),
            'total_ports': int(df['open_port_count'].sum())
        }
        rows = df.to_dict('records')
    return render_template('index.html', stats=stats, rows=rows)

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

@app.route('/download-report')
def download_report():
    try:
        df = load_data()
        if df.empty:
            return jsonify({'error': 'No data available'}), 404

        # Generate HTML report for PDF
        html = """
        <html><head><style>
        body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
        h1 { color: #1a3a5c; border-bottom: 3px solid #2e75b6; padding-bottom: 10px; }
        h2 { color: #1a3a5c; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #1a3a5c; color: white; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-bottom: 1px solid #ddd; }
        .high { color: #991b1b; font-weight: bold; }
        .medium { color: #854d0e; font-weight: bold; }
        .low { color: #166534; font-weight: bold; }
        .explanation { background: #f8fafc; padding: 15px; margin: 10px 0; border-left: 4px solid #2e75b6; border-radius: 4px; }
        </style></head><body>
        <h1>🛡 AI-Assisted Attack Surface Analysis Report</h1>
        <p><strong>Generated:</strong> """ + pd.Timestamp.now().strftime('%Y-%m-%d %H:%M UTC') + """</p>

        <h2>Executive Summary</h2>
        <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Hosts Scanned</td><td>""" + str(df['ip'].nunique()) + """</td></tr>
        <tr><td>High Risk Hosts</td><td class='high'>""" + str(len(df[df['ml_prediction']=='High'])) + """</td></tr>
        <tr><td>Medium Risk Hosts</td><td class='medium'>""" + str(len(df[df['ml_prediction']=='Medium'])) + """</td></tr>
        <tr><td>Low Risk Hosts</td><td class='low'>""" + str(len(df[df['ml_prediction']=='Low'])) + """</td></tr>
        <tr><td>Total Open Ports</td><td>""" + str(int(df['open_port_count'].sum())) + """</td></tr>
        </table>

        <h2>Scan Results</h2>
        <table>
        <tr><th>IP</th><th>Protocol</th><th>Open Ports</th><th>Web</th><th>DB</th><th>Sensitive</th><th>Risk</th></tr>
        """
        for _, row in df.iterrows():
            risk_class = row['ml_prediction'].lower()
            html += f"""<tr>
            <td>{row['ip']}</td>
            <td>{row['protocol'].upper()}</td>
            <td>{row['open_port_count']}</td>
            <td>{'Yes' if row['has_web'] else 'No'}</td>
            <td>{'Yes' if row['has_db'] else 'No'}</td>
            <td>{'Yes' if row['has_sensitive'] else 'No'}</td>
            <td class='{risk_class}'>{row['ml_prediction']}</td>
            </tr>"""

        html += "</table><h2>AI Risk Explanations</h2>"
        for _, row in df.iterrows():
            if 'llm_explanation' in row and row['llm_explanation'] != 'LLM stage not yet run.':
                html += f"""
                <h3>{row['ip']} — {row['protocol'].upper()} — <span class='{row['ml_prediction'].lower()}'>{row['ml_prediction']} Risk</span></h3>
                <div class='explanation'>{row['llm_explanation']}</div>
                """
        html += "</body></html>"

        buffer = io.BytesIO(html.encode('utf-8'))
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype='text/html',
            as_attachment=True,
            download_name='attack_surface_report.html'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        user_message = request.json.get('message', '')
        df = load_data()

        context = ""
        if not df.empty:
            context = f"""Current scan results summary:
- Total hosts: {df['ip'].nunique()}
- High risk: {len(df[df['ml_prediction']=='High'])}
- Medium risk: {len(df[df['ml_prediction']=='Medium'])}
- Low risk: {len(df[df['ml_prediction']=='Low'])}
- Total open ports: {int(df['open_port_count'].sum())}

Detailed results:
{df[['ip','protocol','open_port_count','has_web','has_db','has_sensitive','ml_prediction']].to_string()}
"""

        client = OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))
        resp = client.chat.completions.create(
            model='gpt-3.5-turbo',
            messages=[
                {'role': 'system', 'content': f'You are a cybersecurity analyst assistant. Answer questions about the following network scan results:\n{context}'},
                {'role': 'user', 'content': user_message}
            ],
            max_tokens=500
        )
        return jsonify({'response': resp.choices[0].message.content})
    except Exception as e:
        return jsonify({'response': f'Error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
