import pandas as pd, os 
from openai import OpenAI 
  
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data') 
client   = OpenAI(api_key=os.environ['OPENAI_API_KEY']) 
  
df = pd.read_csv(os.path.join(DATA_DIR, 'ml_results.csv')) 
df = df[df['ip'] != 'synthetic'].copy() 
  
def explain(row): 
    prompt = f"""You are a cybersecurity analyst. Explain the following scan result in 
    exactly 3 parts: 
    1. WHY this host was classified as {row['ml_prediction']} risk 
    2. The main contributing factor to the risk level 
    3. One specific remediation recommendation 
  
Scan data: - IP: {row['ip']} - Protocol: {row['protocol']} - Open ports: {row['open_port_count']} - Has web service: {bool(row['has_web'])} - Has database: {bool(row['has_db'])} - Has sensitive ports: {bool(row['has_sensitive'])} - UDP exposed: {bool(row['is_udp_exposed'])} - ML Risk Classification: {row['ml_prediction']} 
""" 
    resp = client.chat.completions.create( 
        model='gpt-3.5-turbo', 
        messages=[{'role':'user','content':prompt}], 
        max_tokens=300 
    ) 
    return resp.choices[0].message.content 
  
df['llm_explanation'] = df.apply(explain, axis=1) 
df.to_csv(os.path.join(DATA_DIR, 'final_report.csv'), index=False) 
  
for _, row in df.iterrows(): 
    print(f"\n{'='*60}") 
print(f"Host: {row['ip']} | Protocol: {row['protocol']} | Risk: {row['ml_prediction']}")
print(row['llm_explanation']) 
  
print('\n[+] final_report.csv saved.')