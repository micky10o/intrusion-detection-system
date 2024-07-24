import scapy.all as scp
import scapy.arch.windows as scpwinarch
import threading
import queue
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import time
from scapy.all import sniff, IP, TCP, UDP, Raw 
from collections import defaultdict
from PyQt5.QtWidgets import (QApplication, QWidget,QMainWindow, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton,QComboBox, QTabWidget, QStackedWidget, QFrame, QListWidget, QMessageBox, QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont
import sys 



        
#dataset
file_path = 'C:/Users/ECK/Downloads/kdd_train.csv/kdd_train.csv'
data = pd.read_csv(file_path)

# List of features based on the provided image
features_list = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                   'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                   'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                   'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
                   'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                   'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                   'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                   'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                   'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

categorical_features = ['protocol_type', 'service', 'flag']
data_encoded = pd.get_dummies(data, columns=categorical_features)

label_encoder = LabelEncoder()
data_encoded['labels'] = label_encoder.fit_transform(data_encoded['labels'])

X = data_encoded.drop('labels', axis=1)
y = data_encoded['labels']

#normalize data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

#train model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

accuracy = accuracy_score(y_test, rf_model.predict(X_test))
classification_report_str = classification_report(y_test, rf_model.predict(X_test), target_names=label_encoder.classes_, zero_division=1)

print(f"Accuracy: {accuracy}")
print("Classification Report:")
print(classification_report_str)

    # Global variables
pktsummarylist = []
pkt_list = []
updatepktlist = False
stop_sniffing = threading.Event()
pkt_queue = queue.Queue()
connection_counts = {}

    # Service mapping based on port numbers
service_mapping = {
        80: 'http',
        443: 'https',
        21: 'ftp',
        22: 'ssh',
        25: 'smtp',
        53: 'dns',
        110: 'pop3',
        143: 'imap',
        23: 'telnet',
        7:  'echo',
        20: 'ftp_data',
        69: 'tftp',
        88: 'kerberos',
        102: 'iso_tsap',
        137: 'netbios_ns',
        139 : 'netbios_ssn',
        143: 'imap4',
        6665: 'IRC',
        49152: 'private',
        3389: 'remote',
        137: 'nebios',
        57: 'mtp',
        111: 'sunrpc',
        95: 'supdup',
        101: 'hostnames',
        109: 'pop',
        117: 'uucp_path',
        20: 'ftp_data',
        210: 'z39_50',
        105: 'csnet_ns',
        138: 'netbios_dgm',
        30: 'auth',
        389: 'ldap',
        70:  'gopher',
        79: 'finger',
        179: 'bgp',
        1521: 'sql_net',
        540: 'uucp',
        3389: 'remote_job',
        37: 'time',
        512: 'exec',
        84: 'ctf',
        11: 'systat',
        43: 'whois',
        9:  'discord',
        13:  'daytime',
        543: 'klogin',
        544: 'kshell',
        1599: 'urp_i',
        465: 'courier',
        182: 'ecr_i',
        9100: 'vmnet'

    }

all_columns = X.columns.tolist()
    
    
class NIDS(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.sniff_thread = None
        self.update_timer =  QTimer()
        self.update_timer.timeout.connect(self.update_packet_list)
        
    # widgets
    def init_ui(self):
        
        self.setWindowTitle("packet capture and prediction")
        self.setGeometry(100, 100, 800, 600)
           
        
        layout = QVBoxLayout()
        interfacelayout = QHBoxLayout()
        predictionlayout = QVBoxLayout()
        
       # self.interface_frame = QFrame()
        interface_label = QLabel("Select Network Interface:")
        self.interface_menu = QComboBox()
       
        
        
        ifaces = [x["name"] for x in scpwinarch.get_windows_if_list()]
        self.interface_menu.addItems(ifaces)
        
        interfacelayout.addWidget(interface_label)
        interfacelayout.addWidget(self.interface_menu)
        
        #self.interface_frame.setLayout(interfacelayout)
        
        
        
        
        self.start_button = QPushButton('Start Capture',self)
        self.start_button.clicked.connect(self.start_capture)

        self.stop_button = QPushButton('Stop Capture',self)
        self.stop_button.clicked.connect(self.stop_capture)
        
        self.save_button = QPushButton('Save capture',self)
        self.save_button.clicked.connect(self.save_capture)
        
        self.packet_list = QListWidget(self)
        self.packet_list.setMinimumHeight(500)

        
        #self.prediction_frame = QFrame()
        
        prediction_label = QLabel('Predictions:')
        self.prediction_listbox = QListWidget(self)
        #self.prediction_listbox.setMaximumHeight(300)
        
        predictionlayout.addWidget(prediction_label)
        predictionlayout.addWidget(self.prediction_listbox)
        
        #self.prediction_frame.setLayout(predictionlayout)
        

        
        
        layout.addLayout(interfacelayout)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.save_button)
        layout.addWidget(self.packet_list)
        layout.addLayout(predictionlayout)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        
        #self.setLayout(layout)
        
   
    

    #process and extract live packets
    def pkt_process(self,pkt):
        global pkt_list, connection_counts
        pkt_summary = pkt.summary()
        print(f"Captured packet: {pkt_summary}")
        pkt_queue.put(pkt_summary)
        pkt_list.append(pkt)
        
       
        packet_features = self.extract_features(pkt)
        if packet_features is not None:
            packet_features_scaled = scaler.transform([packet_features])
            prediction = rf_model.predict(packet_features_scaled)
            prediction_label = label_encoder.inverse_transform(prediction)
            print(f"Prediction: {prediction_label[0]}")
            
            self.prediction_listbox.addItem(f"Prediction: {prediction_label[0]}")

            #add  sql 
    
    
    def extract_features(self,pkt):
        try:
            global connection_counts

            current_time = time.time()

            # Clean up  entries that are older than 2 seconds
            for ip in list(connection_counts.keys()):
                if current_time - connection_counts[ip]['time'] > 2:
                   del connection_counts[ip]
                   
                   
            src_port = None
            src_ip = None
            dst_ip = None
            sport = None
            dport = None
            service = 'other'
            srv_count = 0
            same_srv_rate = 0.0
            diff_srv_rate = 0.0
            dst_host_same_srv_rate = 0.0
            dst_host_diff_srv_rate = 0.0
            dst_host_same_src_port_rate = 0.0
            dst_host_rerror_rate = 0.0

            if IP in pkt:
                src_port = pkt[IP].sport
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                if dst_ip in connection_counts:
                    connection_counts[dst_ip]['count'] += 1
                else:
                    connection_counts[dst_ip] = {'count': 1, 'time': current_time}

                connection_counts[dst_ip]['time'] = current_time

                count = connection_counts[dst_ip]['count']
            else:
                count = 0

            # Determine the service based on the destination port
            if TCP in pkt or UDP in pkt:
                dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
                sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
                service = service_mapping.get(dport, 'other')
            
                # Calculate srv_count: Number of connections to the same service (same destination port)
                srv_count = sum(1 for conn in connection_counts.values() if conn.get('service') == service)
             
            
                # Calculate same_srv_rate: Proportion of connections to the same service
                if count > 0:
                    same_srv_rate = srv_count / count
                else:
                    same_srv_rate = 0.0
            
            
              # Calculate diff_srv_rate: Rate of change in different services
                if count > 0:
                    diff_srv_rate = (len(set([conn.get('service') for conn in connection_counts.values()])) - 1) / count
                else:
                    diff_srv_rate = 0.0   
            
            
            
                # Calculate dst_host_same_srv_rate: Proportion of connections to the same service on the same host
                dst_host_same_srv_count = sum(1 for conn in connection_counts.values() if conn.get('service') == service and conn.get('dst_ip') == dst_ip)
                if count > 0:
                    dst_host_same_srv_rate = dst_host_same_srv_count / count
                else:
                    dst_host_same_srv_rate = 0.0 
            
            
           
           
                # Calculate dst_host_diff_srv_rate: Rate of change in different services on the same host
                if count > 0:
                    unique_services = set([conn.get('service') for conn in connection_counts.values() if conn.get('dst_ip') == dst_ip])
                    dst_host_diff_srv_rate = (len(unique_services) - 1) / count
                else:
                   dst_host_diff_srv_rate = 0.0 
            
            
                #  Calculate dst_host_same_src_port_rate: Rate of connections from the same src_port to dst_host
                if count > 0:
                    same_src_port_count = sum(1 for conn in connection_counts.values() if conn.get('src_port') == src_port)
                    dst_host_same_src_port_rate = same_src_port_count / count
                else:
                   dst_host_same_src_port_rate = 0.0
            
            
                if count > 0:
                    reset_error_count = sum(1 for conn in connection_counts.values() if conn.get('reset_error', False))
                    dst_host_rerror_rate = reset_error_count / count
                else:
                    dst_host_rerror_rate = 0.0 
                
            else:
                service = 'other'
                srv_count = 0
                same_srv_rate = 0.0
                diff_srv_rate = 0.0 
                dst_host_same_srv_rate = 0.0
                dst_host_diff_srv_rate = 0.0
                dst_host_same_src_port_rate = 0.0
                dst_host_rerror_rate = 0.0
        
        
            # Calculate dst_host_count: Number of connections to the same destination host
            dst_host_count = sum(1 for conn in connection_counts.values() if conn.get('dst_ip') == dst_ip)
        
        
            # Calculate dst_host_srv_count: Number of connections to the same service (same destination port)
            dst_host_srv_count = sum(1 for conn in connection_counts.values() if conn.get('service') == service)



            # Determine the TCP flag
            flag = 'OTH'  # Default flag
            if TCP in pkt:
                flags = pkt[TCP].flags
                flag_map = {
                    'S': 'SYN',
                    'SA': 'SYN/ACK',
                    'A': 'ACK',
                    'F': 'FIN',
                    'R': 'RST',
                    'FA': 'FIN/ACK',
                    'SF': 'SYN/FIN',
                    'S0': 'SYN',
                    'REJ': 'REJ',
                    'RSTR': 'RST',
                    'SH': 'FIN/SYN/ACK',
                    'RSTO': 'RST'
                }
                flag = flag_map.get(flags, 'OTH')
            elif UDP in pkt:
                flags = pkt[UDP].flags
                flag_map = {
                    'S': 'SYN',
                    'SA': 'SYN/ACK',
                    'A': 'ACK',
                    'F': 'FIN',
                    'R': 'RST',
                    'FA': 'FIN/ACK',
                    'SF': 'SYN/FIN',
                    'S0': 'SYN',
                    'REJ': 'REJ',
                    'RSTR': 'RST',
                    'SH': 'FIN/SYN/ACK',
                    'RSTO': 'RST'
                }
                flag = flag_map.get(flags, 'OTH')
            # Calculate the 'hot' feature based on the defined criteria
            hot_indicators = 0
            if Raw in pkt:
                payload = pkt[Raw].load.decode(errors='ignore').lower()
                if "passwd" in payload or "shadow" in payload:
                    hot_indicators += 1  # Example: Accessing sensitive files
                if "select" in payload or "union" in payload:
                    hot_indicators += 1  # Example: SQL injection attempt
                else:
                    hot_indicators = 0
            else: 
                hot_indicators = 0   
                
             # Determine the 'land' feature
            if src_ip == dst_ip and sport == dport:
                land = 1
            else:
                land = 0
            
            
            if IP in pkt:
              features = {
                'duration': float(pkt.time),
                'protocol_type': pkt.proto if pkt.proto in ['tcp', 'udp', 'icmp'] else 'other',
                'service': service,
                'flag': flag,
                'src_bytes': float(len(pkt)),
                'dst_bytes': float(len(pkt)),
                'land': land,  # Modify as necessary
                'wrong_fragment': 0,  # Modify as necessary
                'urgent': 0,  # Modify as necessary
                'hot': hot_indicators,  # Use the calculated hot indicators
                'num_failed_logins': 0,  # Modify as necessary
                'logged_in': 0,  # Modify as necessary
                'num_compromised': 0,  # Modify as necessary
                'root_shell': 0,  # Modify as necessary
                'su_attempted': 0,  # Modify as necessary
                'num_root': 0,  # Modify as necessary
                'num_file_creations': 0,  # Modify as necessary
                'num_shells': 0,  # Modify as necessary
                'num_access_files': 0,  # Modify as necessary
                'num_outbound_cmds': 0,  # Modify as necessary
                'is_host_login': 0,  # Modify as necessary
                'is_guest_login': 0,  # Modify as necessary
                'count': count,
                'srv_count': srv_count,  # Modify as necessary
                'serror_rate': 0.0,  # Modify as necessary
                'srv_serror_rate': 0.0,  # Modify as necessary
                'rerror_rate': 0.0,  # Modify as necessary
                'srv_rerror_rate': 0.0,  # Modify as necessary
                'same_srv_rate': same_srv_rate,  # Modify as necessary
                'diff_srv_rate': diff_srv_rate,  # Modify as necessary
                'srv_diff_host_rate': 0.0,  # Modify as necessary
                'dst_host_count': dst_host_count,  # Modify as necessary
                'dst_host_srv_count': dst_host_srv_count,  # Modify as necessary
                'dst_host_same_srv_rate': dst_host_same_srv_rate,  # Modify as necessary
                'dst_host_diff_srv_rate': dst_host_diff_srv_rate,  # Modify as necessary
                'dst_host_same_src_port_rate': dst_host_same_src_port_rate,  # Modify as necessary
                'dst_host_srv_diff_host_rate': 0.0,  # Modify as necessary
                'dst_host_serror_rate': 0.0,  # Modify as necessary
                'dst_host_srv_serror_rate': 0.0,  # Modify as necessary
                'dst_host_rerror_rate':  dst_host_rerror_rate ,  # Modify as necessary
                'dst_host_srv_rerror_rate': 0.0  # Modify as necessary
              }

            # One-hot encoding of categorical features
              encoded_features = {}
              for column in all_columns:
                if column.startswith('protocol_type_'):
                    proto = column.split('_')[-1]
                    encoded_features[column] = 1 if features['protocol_type'] == proto else 0
                elif column.startswith('service_'):
                    svc = column.split('_')[-1]
                    encoded_features[column] = 1 if features['service'] == svc else 0
                elif column.startswith('flag_'):
                    flg = column.split('_')[-1]
                    encoded_features[column] = 1 if features['flag'] == flg else 0
                else:
                    encoded_features[column] = features.get(column, 0)

              return list(encoded_features.values())
            return None
        
            
           
 
        except AttributeError as e:
            print(f"AttributeError: {e}")
        return None
    
    #get packets
    def sniff_packets(self, iface):
        sniff(iface=iface, prn=self.pkt_process, stop_filter=lambda x: stop_sniffing.is_set())
    
    #start capturing packets
    def start_capture(self):
        global updatepktlist
        updatepktlist= True
        selected_iface = self.interface_menu.currentText()
        if not selected_iface:
            QMessageBox.information("Error","Please select an interface")
            return
        stop_sniffing.clear()
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(selected_iface,))
        self.sniff_thread.start()
        self.update_timer.start(1000)
    
    #stop capturing packets
    def stop_capture(self):
        global updatepktlist
        stop_sniffing.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join()
        self.update_timer.stop()
    
    #save captured packets
    def save_capture(self):
        file_path = 'C:/Users/ECK/Desktop/capturedpackets/captured_packets.csv'
        with open(file_path, 'w') as f:
            for pkt in pkt_list:
                f.write(f"{pkt}\n")
        QMessageBox.information(self, "Save Capture", "Capture saved  " )

    def update_packet_list(self):
        while not pkt_queue.empty():
            pkt_summary = pkt_queue.get()
            self.packet_list.addItem(pkt_summary)
        if not stop_sniffing.is_set():
            self.update_timer.start(1000)
        

            
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = NIDS()
    ex.show()
    sys.exit(app.exec_())

    
        
       
           
        

        
        
        
        
        
