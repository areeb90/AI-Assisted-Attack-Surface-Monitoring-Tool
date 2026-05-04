import pandas as pd, os, joblib 
from sklearn.tree import DecisionTreeClassifier, export_text 
from sklearn.ensemble import RandomForestClassifier 
from sklearn.model_selection import train_test_split 
from sklearn.metrics import accuracy_score 
  
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data') 
ML_DIR   = os.path.dirname(__file__) 
  
FEATURES = ['open_port_count','has_web','has_db','has_sensitive','is_udp_exposed'] 
  
train = pd.read_csv(os.path.join(DATA_DIR, 'training_dataset.csv')) 
real  = pd.read_csv(os.path.join(DATA_DIR, 'attack_surface_features.csv')) 
labeled = pd.read_csv(os.path.join(DATA_DIR, 'labeled_features.csv')) 
  
X = train[FEATURES]; y = train['risk_label'] 
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42) 
  
dt = DecisionTreeClassifier(max_depth=4, random_state=42) 
dt.fit(X_train, y_train) 
print('Decision Tree Rules:') 
print(export_text(dt, feature_names=FEATURES)) 
print(f'DT Accuracy: {accuracy_score(y_test, dt.predict(X_test)):.2f}') 
  
rf = RandomForestClassifier(n_estimators=100, random_state=42) 
rf.fit(X_train, y_train) 
print(f'RF Accuracy: {accuracy_score(y_test, rf.predict(X_test)):.2f}') 
  
joblib.dump(rf, os.path.join(ML_DIR, 'rf_model.pkl')) 
  
real_X = real[FEATURES] 
real['ml_prediction'] = rf.predict(real_X) 
labeled['ml_prediction'] = rf.predict(labeled[FEATURES]) 
  
out = labeled[['ip','protocol','open_port_count','has_web','has_db', 
               'has_sensitive','is_udp_exposed','risk_label','ml_prediction']] 
out.to_csv(os.path.join(DATA_DIR, 'ml_results.csv'), index=False) 
print(out.to_string()) 
print('[+] Model saved. ml_results.csv written.')