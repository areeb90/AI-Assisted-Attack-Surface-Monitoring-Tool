from flask import Flask, render_template, jsonify, request, send_file, Response
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

def get_openai_client():
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        return None, "OPENAI_API_KEY is not set. Run: export OPENAI_API_KEY='your-key' then restart Flask."
    return OpenAI(api_key=api_key), None

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

# @app.route('/print-report')
# def print_report():
#    df = load_data()
#    data = df.to_dict('records') if not df.empty else []
#    return render_template('print_report.html', data=data)



@app.route('/print-report')
def print_report():
    df = load_data()
    data = df.to_dict('records') if not df.empty else []
    now = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M UTC')
    return render_template('print_report.html', data=data, now=now)


@app.route('/download-report')
def download_report():
    try:
        df = load_data()
        if df.empty:
            return "No data available. Run the pipeline first.", 404

        generated_at = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M UTC')
        total_hosts  = df['ip'].nunique()
        high_count   = len(df[df['ml_prediction']=='High'])
        med_count    = len(df[df['ml_prediction']=='Medium'])
        low_count    = len(df[df['ml_prediction']=='Low'])
        total_ports  = int(df['open_port_count'].sum())

        rows_html = ""
        for _, row in df.iterrows():
            rc = row['ml_prediction'].lower()
            rows_html += f"""
            <tr>
              <td class="mono">{row['ip']}</td>
              <td>{row['protocol'].upper()}</td>
              <td>{row['open_port_count']}</td>
              <td>{'✓' if row['has_web'] else '✗'}</td>
              <td>{'✓' if row['has_db'] else '✗'}</td>
              <td>{'✓' if row['has_sensitive'] else '✗'}</td>
              <td><span class="badge {rc}">{row['ml_prediction']}</span></td>
            </tr>"""

        explanations_html = ""
        for _, row in df.iterrows():
            expl = row.get('llm_explanation', '')
            if expl and expl != 'LLM stage not yet run.':
                rc = row['ml_prediction'].lower()
                explanations_html += f"""
                <div class="expl-card {rc}">
                  <div class="expl-header">
                    <span class="mono">{row['ip']}</span>
                    <span class="proto">{row['protocol'].upper()}</span>
                    <span class="badge {rc}">{row['ml_prediction']} Risk</span>
                  </div>
                  <div class="expl-body">{expl}</div>
                </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Attack Surface Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:Arial,sans-serif;background:#f8fafc;color:#1e293b;padding:40px}}
.page{{max-width:900px;margin:0 auto;background:white;padding:48px;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,0.08)}}
.header{{border-bottom:3px solid #2e75b6;padding-bottom:24px;margin-bottom:32px}}
.header h1{{font-size:1.8em;color:#0d1f35;font-weight:700}}
.header p{{color:#64748b;margin-top:6px;font-size:0.9em}}
.summary-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:32px}}
.summary-card{{padding:16px;border-radius:10px;text-align:center}}
.summary-card .val{{font-size:2em;font-weight:700}}
.summary-card .lbl{{font-size:0.72em;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px;opacity:0.7}}
.blue{{background:#dbeafe;color:#1e3a5f}}
.red-bg{{background:#fee2e2;color:#7f1d1d}}
.yellow-bg{{background:#fef9c3;color:#713f12}}
.green-bg{{background:#dcfce7;color:#14532d}}
.grey-bg{{background:#f1f5f9;color:#334155}}
h2{{font-size:1.1em;font-weight:700;color:#0d1f35;margin:28px 0 14px;padding-bottom:8px;border-bottom:2px solid #e2e8f0}}
table{{width:100%;border-collapse:collapse;font-size:0.88em}}
thead{{background:#0d1f35}}
th{{color:white;padding:10px 12px;text-align:left;font-size:0.8em;text-transform:uppercase;letter-spacing:0.4px}}
td{{padding:10px 12px;border-bottom:1px solid #f0f4f8}}
.mono{{font-family:monospace;font-size:0.9em}}
.badge{{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.78em;font-weight:700;text-transform:uppercase}}
.badge.high{{background:#fee2e2;color:#dc2626}}
.badge.medium{{background:#fef9c3;color:#d97706}}
.badge.low{{background:#dcfce7;color:#16a34a}}
.expl-card{{border-radius:10px;border-left:5px solid;padding:20px;margin:14px 0;background:#f8fafc}}
.expl-card.high{{border-left-color:#dc2626}}
.expl-card.medium{{border-left-color:#d97706}}
.expl-card.low{{border-left-color:#16a34a}}
.expl-header{{display:flex;gap:10px;align-items:center;margin-bottom:10px}}
.proto{{background:#e2e8f0;padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:600}}
.expl-body{{font-size:0.88em;line-height:1.75;white-space:pre-wrap;color:#334155}}
.footer{{margin-top:40px;padding-top:16px;border-top:1px solid #e2e8f0;font-size:0.78em;color:#94a3b8;text-align:center}}
</style></head><body>
<div class="page">
  <div class="header">
    <h1>⬡ AI-Assisted Attack Surface Analysis Report</h1>
    <p>Generated: {generated_at} &nbsp;|&nbsp; Areeb Bin Azim — B01034028</p>
  </div>
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-card blue"><div class="val">{total_hosts}</div><div class="lbl">Hosts Scanned</div></div>
    <div class="summary-card red-bg"><div class="val">{high_count}</div><div class="lbl">High Risk</div></div>
    <div class="summary-card yellow-bg"><div class="val">{med_count}</div><div class="lbl">Medium Risk</div></div>
    <div class="summary-card green-bg"><div class="val">{low_count}</div><div class="lbl">Low Risk</div></div>
    <div class="summary-card grey-bg"><div class="val">{total_ports}</div><div class="lbl">Open Ports</div></div>
  </div>
  <h2>Scan Results</h2>
  <table><thead><tr><th>IP Address</th><th>Protocol</th><th>Open Ports</th><th>Web</th><th>Database</th><th>Sensitive</th><th>ML Risk</th></tr></thead>
  <tbody>{rows_html}</tbody></table>
  <h2>AI Risk Explanations</h2>
  {explanations_html if explanations_html else '<p style="color:#94a3b8;font-size:0.9em;">No LLM explanations available.</p>'}
  <div class="footer">AI-Assisted Risk Analysis &nbsp;|&nbsp; {generated_at}</div>
</div></body></html>"""

        buf = io.BytesIO(html.encode('utf-8'))
        buf.seek(0)
        return Response(
            buf.getvalue(),
            mimetype='application/octet-stream',
            headers={'Content-Disposition': 'attachment; filename="attack_surface_report.html"'}
        )
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/api/chat', methods=['POST'])
def chat():
    client, err = get_openai_client()
    if err:
        return jsonify({'response': f'⚠️ {err}'}), 200
    try:
        user_message = request.json.get('message', '').strip()
        if not user_message:
            return jsonify({'response': 'Please type a question.'}), 200

        df = load_data()
        context = "No scan data available yet."
        if not df.empty:
            context = f"""Network scan results summary:
- Hosts scanned: {df['ip'].nunique()}
- High risk: {len(df[df['ml_prediction']=='High'])}
- Medium risk: {len(df[df['ml_prediction']=='Medium'])}
- Low risk: {len(df[df['ml_prediction']=='Low'])}
- Total open ports: {int(df['open_port_count'].sum())}

Per-host breakdown:
{df[['ip','protocol','open_port_count','has_web','has_db','has_sensitive','is_udp_exposed','ml_prediction']].to_string(index=False)}

ML model: Random Forest, 95% accuracy
Risk thresholds: Low<=4, Medium<=10, High>10"""

        resp = client.chat.completions.create(
            model='gpt-3.5-turbo',
            messages=[
                {'role': 'system', 'content': f'You are a senior cybersecurity analyst. Be concise and reference actual IPs and ports. Context:\n{context}'},
                {'role': 'user', 'content': user_message}
            ],
            max_tokens=600
        )
        return jsonify({'response': resp.choices[0].message.content})
    except Exception as e:
        return jsonify({'response': f'Error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
