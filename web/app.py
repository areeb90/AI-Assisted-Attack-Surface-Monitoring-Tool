from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
import pandas as pd, os, subprocess, io, json, time, threading, hashlib
from datetime import datetime
from openai import OpenAI

app = Flask(__name__)
app.secret_key = 'attacksurface-secret-key-2026'

DATA_DIR     = os.path.join(os.path.dirname(__file__), '..', 'data')
HISTORY_FILE = os.path.join(DATA_DIR, 'scan_history.json')
PROGRESS_FILE= os.path.join(DATA_DIR, 'pipeline_progress.json')

# ── Auth config ───────────────────────────────────────────
# USERS = {
#    'admin': hashlib.sha256('admin123'.encode()).hexdigest(),
#    'areeb': hashlib.sha256('seminar2026'.encode()).hexdigest(),
# }



USERS = {
    'admin': 'admin123',
    'areeb': 'seminar2026',
}



# ── Email config (edit these) ─────────────────────────────
EMAIL_CONFIG = {
    'enabled': False,           # Set True after configuring
    'smtp_host': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender': 'your@gmail.com',
    'password': 'your-app-password',
    'recipient': 'your@gmail.com',
}

# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────
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
        return None, "OPENAI_API_KEY not set. Run: export OPENAI_API_KEY='your-key' then restart Flask."
    return OpenAI(api_key=api_key), None

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def write_progress(stage, status, pct):
    with open(PROGRESS_FILE, 'w') as f:
        json.dump({'stage': stage, 'status': status, 'pct': pct, 'ts': time.time()}, f)

def save_scan_history():
    df = load_data()
    if df.empty:
        return
    entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_hosts': int(df['ip'].nunique()),
        'high': int(len(df[df['ml_prediction']=='High'])),
        'medium': int(len(df[df['ml_prediction']=='Medium'])),
        'low': int(len(df[df['ml_prediction']=='Low'])),
        'total_ports': int(df['open_port_count'].sum()),
    }
    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            history = json.load(f)
    history.append(entry)
    history = history[-20:]  # keep last 20 runs
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def send_alert_email(high_hosts):
    if not EMAIL_CONFIG['enabled']:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        body = f"⚠️ HIGH RISK ALERT — Attack Surface Scan\n\n"
        body += f"Detected {len(high_hosts)} high-risk host(s):\n\n"
        for h in high_hosts:
            body += f"  • {h['ip']} ({h['protocol'].upper()}) — {h['open_port_count']} open ports\n"
        body += f"\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        msg = MIMEText(body)
        msg['Subject'] = f'[ALERT] {len(high_hosts)} High-Risk Host(s) Detected'
        msg['From'] = EMAIL_CONFIG['sender']
        msg['To'] = EMAIL_CONFIG['recipient']
        with smtplib.SMTP(EMAIL_CONFIG['smtp_host'], EMAIL_CONFIG['smtp_port']) as s:
            s.starttls()
            s.login(EMAIL_CONFIG['sender'], EMAIL_CONFIG['password'])
            s.send_message(msg)
    except Exception as e:
        print(f'[EMAIL ERROR] {e}')

def run_pipeline_with_progress():
    stages = [
        ('Stage 1: Network Scan (Nmap)',   'sudo bash scanner/scan.sh',       20),
        ('Stage 2: Feature Extraction',    'python3 scanner/parse_nmap.py',   40),
        ('Stage 3: Label Dataset',         'python3 scanner/label_dataset.py',60),
        ('Stage 4: Train ML Models',       'python3 ml/train_model.py',       80),
        ('Stage 5: LLM Explanations',      'python3 llm/llm_explain.py',     100),
    ]
    write_progress('Starting...', 'running', 0)
    for name, cmd, pct in stages:
        write_progress(name, 'running', pct - 18)
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            write_progress(name, f'error: {result.stderr[:200]}', pct - 18)
            return
        write_progress(name, 'done', pct)
        time.sleep(0.5)
    save_scan_history()
    # Send email alert if high risk found
    df = load_data()
    if not df.empty:
        high = df[df['ml_prediction']=='High'].to_dict('records')
        if high:
            send_alert_email(high)
    write_progress('Complete', 'complete', 100)

# ─────────────────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        hashed   = hashlib.sha256(password.encode()).hexdigest()
        if username in USERS and USERS[username] == password:
            session['logged_in'] = True
            session['username']  = username
            return redirect(url_for('index'))
        error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─────────────────────────────────────────────────────────
# Main Routes
# ─────────────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    df = load_data()
    stats, rows = {}, []
    if not df.empty:
        stats = {
            'total_hosts': df['ip'].nunique(),
            'high':   len(df[df['ml_prediction']=='High']),
            'medium': len(df[df['ml_prediction']=='Medium']),
            'low':    len(df[df['ml_prediction']=='Low']),
            'total_ports': int(df['open_port_count'].sum()),
        }
        rows = df.to_dict('records')
    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            history = json.load(f)
    return render_template('index.html', stats=stats, rows=rows,
                           history=history, username=session.get('username',''))

@app.route('/results')
@login_required
def results():
    df = load_data()
    data = df.to_dict('records') if not df.empty else []
    return render_template('results.html', data=data)

@app.route('/report')
@login_required
def report():
    df = load_data()
    data = df.to_dict('records') if not df.empty else []
    return render_template('report.html', data=data)

@app.route('/api/results')
@login_required
def api_results():
    df = load_data()
    return jsonify(df.to_dict('records') if not df.empty else [])

@app.route('/api/history')
@login_required
def api_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            return jsonify(json.load(f))
    return jsonify([])

# ─────────────────────────────────────────────────────────
# Pipeline Routes
# ─────────────────────────────────────────────────────────
@app.route('/run-pipeline', methods=['POST'])
@login_required
def run_pipeline():
    write_progress('Starting...', 'running', 0)
    t = threading.Thread(target=run_pipeline_with_progress, daemon=True)
    t.start()
    return jsonify({'status': 'Pipeline started'})

@app.route('/api/pipeline-progress')
@login_required
def pipeline_progress():
    if not os.path.exists(PROGRESS_FILE):
        return jsonify({'stage': 'idle', 'status': 'idle', 'pct': 0})
    with open(PROGRESS_FILE) as f:
        return jsonify(json.load(f))

# ─────────────────────────────────────────────────────────
# Re-scan Single Host
# ─────────────────────────────────────────────────────────
@app.route('/rescan/<ip>', methods=['POST'])
@login_required
def rescan_host(ip):
    import re
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        return jsonify({'status': 'Invalid IP'}), 400
    def do_rescan():
        write_progress(f'Re-scanning {ip}', 'running', 10)
        subprocess.run(
            f'sudo nmap -sS -p- -T4 --open -oX {DATA_DIR}/scan_tcp_{ip}.xml '
            f'-oN {DATA_DIR}/scan_tcp_{ip}.txt {ip}',
            shell=True
        )
        subprocess.run(
            f'sudo nmap -sU --top-ports 20 -T4 -oX {DATA_DIR}/scan_udp_{ip}.xml '
            f'-oN {DATA_DIR}/scan_udp_{ip}.txt {ip}',
            shell=True
        )
        write_progress(f'Re-scanning {ip}', 'running', 60)
        subprocess.run('python3 scanner/parse_nmap.py',   shell=True)
        subprocess.run('python3 scanner/label_dataset.py',shell=True)
        subprocess.run('python3 ml/train_model.py',       shell=True)
        write_progress(f'Re-scan of {ip} complete', 'complete', 100)
    t = threading.Thread(target=do_rescan, daemon=True)
    t.start()
    return jsonify({'status': f'Re-scan started for {ip}'})

# ─────────────────────────────────────────────────────────
# Chat
# ─────────────────────────────────────────────────────────
@app.route('/api/chat', methods=['POST'])
@login_required
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
            context = f"""Network scan results:
- Hosts: {df['ip'].nunique()} | High: {len(df[df['ml_prediction']=='High'])} | Medium: {len(df[df['ml_prediction']=='Medium'])} | Low: {len(df[df['ml_prediction']=='Low'])}
- Total open ports: {int(df['open_port_count'].sum())}
Per-host:
{df[['ip','protocol','open_port_count','has_web','has_db','has_sensitive','is_udp_exposed','ml_prediction']].to_string(index=False)}
ML: Random Forest 95% accuracy. Risk: Low<=4, Medium<=10, High>10"""
        resp = client.chat.completions.create(
            model='gpt-3.5-turbo',
            messages=[
                {'role':'system','content':f'You are a senior cybersecurity analyst. Be concise, specific, reference actual IPs. Context:\n{context}'},
                {'role':'user','content':user_message}
            ],
            max_tokens=600
        )
        return jsonify({'response': resp.choices[0].message.content})
    except Exception as e:
        return jsonify({'response': f'Error: {str(e)}'}), 500

# ─────────────────────────────────────────────────────────
# Download / Print
# ─────────────────────────────────────────────────────────
@app.route('/print-report')
@login_required
def print_report():
    df = load_data()
    data = df.to_dict('records') if not df.empty else []
    now = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
    return render_template('print_report.html', data=data, now=now)

if __name__ == '__main__':
    os.makedirs(DATA_DIR, exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
