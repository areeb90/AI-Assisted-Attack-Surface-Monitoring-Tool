import pandas as pd, os, random 
  
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data') 
  
def score_row(row): 
    s = 0 
    s += min(row['open_port_count'] * 2, 10) 
    s += row['has_web'] * 3 
    s += row['has_db'] * 4 
    s += row['has_sensitive'] * 2 
    s += row['is_udp_exposed'] * 3 
    return s 
  
def label(score): 
    if score <= 4: return 'Low' 
    if score <= 10: return 'Medium' 
    return 'High' 
  
df = pd.read_csv(os.path.join(DATA_DIR, 'attack_surface_features.csv')) 
df['risk_score'] = df.apply(score_row, axis=1) 
df['risk_label'] = df['risk_score'].apply(label) 
  
# Synthetic training data 
random.seed(42) 
synth = [] 
for _ in range(300): 
    pc = random.randint(0, 20) 
    hw = random.randint(0, 1) 
    hd = random.randint(0, 1) 
    hs = random.randint(0, 1) 
    iu = random.randint(0, 1) 
    s  = min(pc*2,10) + hw*3 + hd*4 + hs*2 + iu*3 
    synth.append({'ip':'synthetic','protocol':'tcp','open_port_count':pc, 
                  'has_web':hw,'has_db':hd,'has_sensitive':hs, 
                  'is_udp_exposed':iu,'risk_score':s,'risk_label':label(s)}) 

  
train_df = pd.concat([df, pd.DataFrame(synth)], ignore_index=True) 
train_df.to_csv(os.path.join(DATA_DIR, 'training_dataset.csv'), index=False) 
df.to_csv(os.path.join(DATA_DIR, 'labeled_features.csv'), index=False) 
  
print(train_df['risk_label'].value_counts()) 
print(f'[+] Saved training_dataset.csv ({len(train_df)} rows)')