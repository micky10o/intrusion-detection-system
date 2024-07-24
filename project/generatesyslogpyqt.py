import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QListWidget,QLabel, QPushButton, QVBoxLayout, QWidget, QMessageBox
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QTextCursor,QTextCharFormat, QColor
import win32evtlog
import win32evtlogutil
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.callbacks import EarlyStopping
import joblib
import os


#  dataset
file_path = 'C:/Users/ECK/Desktop/csv/combinedlog3.csv'
df = pd.read_csv(file_path)

# Handle missing values
df = df.fillna('Unknown')

# Convert categorical features to numeric using one-hot encoding

encoder = OneHotEncoder(handle_unknown='ignore')
source_encoded= encoder.fit_transform(df[['Source']]).toarray()

# TF-IDF Vectorization for 'General' feature
vectorizer = TfidfVectorizer(max_features=1000)  # Adjust max_features as needed
general_tfidf = vectorizer.fit_transform(df['General']).toarray()


# Convert 'Event ID' to numeric
df['Event ID'] = pd.to_numeric(df['Event ID'], errors='coerce').fillna(0)

# Combine encoded features with 'Event ID'
features = np.hstack((source_encoded,general_tfidf, df[['Event ID']].values))

# Normalize the data
scaler = StandardScaler()
data_scaled = scaler.fit_transform(features)

#convert data to float32 for memory eff
data_scaled = data_scaled.astype(np.float32)


# Use memory-mapped files for training and testing data
memmap_filename = 'C:/Users/ECK/Desktop/csv/memmap_data.dat'
joblib.dump(data_scaled, memmap_filename)
data_memmap = joblib.load(memmap_filename, mmap_mode='r+')


# Split the data into training and testing sets
X_train, X_test = train_test_split(data_memmap, test_size=0.2, random_state=42)

#  autoencoder model
input_dim = X_train.shape[1]
encoding_dim = int(input_dim / 2)  #  encoding dimension

input_layer = Input(shape=(input_dim,))
encoder_layer = Dense(encoding_dim, activation="relu")(input_layer)
decoder_layer = Dense(input_dim, activation="sigmoid")(encoder_layer)

autoencoder = Model(inputs=input_layer, outputs=decoder_layer)
autoencoder.compile(optimizer="adam", loss="mean_squared_error")


early_stopping = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)


# Train the autoencoder
history = autoencoder.fit(X_train, X_train, 
                          epochs=50,
                          batch_size=64,
                          shuffle=True,
                          validation_data=(X_test, X_test),
                          callbacks=[early_stopping])

# Evaluate the model
reconstructed_data = autoencoder.predict(X_test)
mse = np.mean(np.power(X_test - reconstructed_data, 2), axis=1)

# Set a threshold for anomaly detection
threshold = np.percentile(mse, 95)  

# Detect anomalies
anomalies = mse > threshold



# Print results
print(f"Number of anomalies detected: {np.sum(anomalies)}")
print("Indices of anomalies:", np.where(anomalies)[0])



class RealTimeLogViewer(QMainWindow):
    #widgets
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Real-Time Log Viewer")
        self.setGeometry(100, 100, 800, 600)
        
        self.log_text = QListWidget(self)
        

        self.start_button = QPushButton("Start Logging", self)
        self.start_button.clicked.connect(self.start_logging)

        self.stop_button = QPushButton("Stop Logging", self)
        self.stop_button.setDisabled(True)
        self.stop_button.clicked.connect(self.stop_logging)
        
        predictlayout = QVBoxLayout()
        predict_label = QLabel('prediction:')
        self.predict_list = QListWidget(self)
        
        predictlayout.addWidget(predict_label)
        predictlayout.addWidget(self.predict_list)

        layout = QVBoxLayout()
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.log_text)
        layout.addLayout(predictlayout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.is_logging = False
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_logs)
    
    #function to start loging
    def start_logging(self):
        if not self.is_logging:
            self.is_logging = True
            self.start_button.setDisabled(True)
            self.stop_button.setDisabled(False)
            self.timer.start(1000)
    #function to stop loging
    def stop_logging(self):
        self.is_logging = False
        self.start_button.setDisabled(False)
        self.stop_button.setDisabled(True)
        self.timer.stop()
    #preprocess live logs
    def preprocess_log(self, log_entry):
        log_df = pd.DataFrame([log_entry], columns=['Source', 'General', 'Event ID'])
        log_df = log_df.fillna('Unknown')
        source_encoded = encoder.transform(log_df[['Source']]).toarray()
        general_tfidf = vectorizer.transform(log_df['General']).toarray()
        event_id = pd.to_numeric(log_df['Event ID'], errors='coerce').fillna(0).values.reshape(-1, 1)
        features = np.hstack((source_encoded, general_tfidf, event_id))
        scaled_features = scaler.transform(features)
        return scaled_features.astype(np.float32)

    #generate live logs
    def update_logs(self):
        if not self.is_logging:
            return

        server = 'localhost'
        log_types = ['System', 'Application']

        try:
            for log_type in log_types:
                handle = win32evtlog.OpenEventLog(server, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(handle, flags, 0)

                for event in events:
                    time_created = event.TimeGenerated.Format()
                    source = event.SourceName
                    event_id = event.EventID & 0xFFFF  # Extract the lower 16 bits

                    try:
                        message = win32evtlogutil.SafeFormatMessage(event, log_type)
                    except Exception as e:
                        message = f"Failed to format message: {e}"

                    log_entry = f"{time_created} - {source} - Event ID: {event_id}\n{message}\n\n"
                    self.log_text.addItem(log_entry)
                
                      # Preprocess the log for prediction
                    log_features = {'Source': source, 'General': message, 'Event ID': event_id}
                    scaled_log = self.preprocess_log(log_features)

                    # Predict using the autoencoder
                    reconstructed_log = autoencoder.predict(scaled_log)
                    mse_log = np.mean(np.power(scaled_log - reconstructed_log, 2), axis=1)
                    is_anomalous = mse_log > threshold

                    if is_anomalous:
                        self.predict_list.addItem("Anomaly detected")
                        
                    else:
                        self.predict_list.addItem("normal")
                        #add prediction for sql


        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read logs: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    viewer = RealTimeLogViewer()
    viewer.show()
    sys.exit(app.exec_())
