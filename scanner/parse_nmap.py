import glob, os 
import pandas as pd 
from lxml import etree 
  
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data') 
  
def parse_xml(filepath): 
    tree = etree.parse(filepath) 
    root = tree.getroot() 
    results = [] 
    for host in root.findall('host'): 
        addr = host.find('address').get('addr') 
        ports = host.find('ports') 
        if ports is None: 
            continue 
        open_ports = [] 
        for port in ports.findall('port'): 
            state = port.find('state').get('state') 
            if state == 'open': 
                open_ports.append(int(port.get('portid'))) 
        results.append({'ip': addr, 'open_ports': open_ports, 
                        'is_udp': 'udp' in filepath}) 
    return results 
  
def extract_features(scan_result): 
    ports = scan_result['open_ports'] 
    return { 
        'ip': scan_result['ip'], 
        'protocol': 'udp' if scan_result['is_udp'] else 'tcp', 
        'open_port_count': len(ports), 
        'has_web': int(80 in ports or 443 in ports or 8080 in ports), 
        'has_db': int(3306 in ports or 5432 in ports or 1433 in ports), 
        'has_sensitive': int(22 in ports or 3389 in ports or 23 in ports), 
        'is_udp_exposed': int(scan_result['is_udp'] and len(ports) > 0), 
    } 
  
all_features = []


for xml_file in glob.glob(os.path.join(DATA_DIR, 'scan_*.xml')): 
    for result in parse_xml(xml_file): 
        all_features.append(extract_features(result)) 
  
df = pd.DataFrame(all_features) 
out_path = os.path.join(DATA_DIR, 'attack_surface_features.csv') 
df.to_csv(out_path, index=False) 
print(df.to_string()) 
print(f'\n[+] Features saved to {out_path}') 