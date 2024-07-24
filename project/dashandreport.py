from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton,QTableWidget, QTableWidgetItem,QTabWidget, QStackedWidget, QFrame, QListWidget, QMessageBox, QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDate, QTime
from PyQt5.QtGui import QFont
from PyQt5.QtSql import QSqlDatabase, QSqlQuery
import sys 
from NIDSpyqt import NIDS


class NetTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        
        
        netlayout = QVBoxLayout()
        
        self.networktable = QTableWidget()
        self.networktable.setColumnCount(5)
        self.networktable.setHorizontalHeaderLabels(["Id", "Packet", "Prediction", "Time", "Date"])
        
        self.net_button = QPushButton("delete",self)
        
        netlayout.addWidget(self.networktable)
        netlayout.addWidget(self.net_button)
        self.setLayout(netlayout)
        
        #self.load_networktable()
        
    """
        
    def load_networktable(self):
        self.networktable.setRowCount(0)
    
        query = QSqlQuery("SELECT * FROM NetworkTable")
        row = 0
        while query.next():
            Id = query.value(0)
            Packet = query.value(1)
            Prediction = query.value(2)
            Time = query.value(3)
            Date = query.value(4)
        
            self.networktable.insertRow(row)
            self.networktable.setItem(row,0,QTableWidgetItem(str(Id)))
            self.networktable.setItem(row,1,QTableWidgetItem(Packet))
            self.networktable.setItem(row,2,QTableWidgetItem(Prediction))
            self.networktable.setItem(row,3,QTableWidgetItem(Time))
            self.networktable.setItem(row,4,QTableWidgetItem(Date))
        
        
            row += 1        
    """    

class HostTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        
        hostlayout = QVBoxLayout()
        
        self.hosttable = QTableWidget()
        self.hosttable.setColumnCount(7)
        self.hosttable.setHorizontalHeaderLabels(["Id", "Source","Event ID","General", "Prediction", "Time", "Date"])
        
        self.host_button = QPushButton("delete",self)
        
        hostlayout.addWidget(self.hosttable)
        hostlayout.addWidget(self.host_button)
        self.setLayout(hostlayout)
        
       # self.load_hosttable()
        
    """  
    def load_hosttable(self):
        self.hosttable.setRowCount(0)
    
        query = QSqlQuery("SELECT * FROM HostTable")
        row = 0
        while query.next():
            Id = query.value(0)
            Source = query.value(1)
            Event_ID = query.value(2)
            General = query.value(3)
            Prediction = query.value(4)
            Time = query.value(5)
            Date = query.value(6)
        
            self.hosttable.insertRow(row)
            self.hosttable.setItem(row,0,QTableWidgetItem(str(Id)))
            self.hosttable.setItem(row,1,QTableWidgetItem(Source))
            self.hosttable.setItem(row,1,QTableWidgetItem(str(Event_ID)))
            self.hosttable.setItem(row,1,QTableWidgetItem(General))
            self.hosttable.setItem(row,2,QTableWidgetItem(Prediction))
            self.hosttable.setItem(row,3,QTableWidgetItem(Time))
            self.hosttable.setItem(row,4,QTableWidgetItem(Date))
        
        
            row += 1
        
    """   

class Report(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
        
    def init_ui(self):
        layout = QVBoxLayout()
        self.tab_widget = QTabWidget()
        
        self.devicetable = QTableWidget()
        self.devicetable.setColumnCount(5)
        self.devicetable.setHorizontalHeaderLabels(["Id", "Device", "State", "Time", "Date"])
        
        self.apptable = QTableWidget()
        self.apptable.setColumnCount(5)
        self.apptable.setHorizontalHeaderLabels(["Id", "App", "State", "Time", "Date"])
        
        self.sitetable = QTableWidget()
        self.sitetable.setColumnCount(5)
        self.sitetable.setHorizontalHeaderLabels(["Id", "Site", "State", "Time", "Date"])
        
        
        
        
       
        
        self.blocked_devices = self.devicetable
        self.blocked_apps  = self.apptable
        self.blocked_site = self.sitetable
        self.NIDS = NetTab()
        self.HIDS = HostTab()
        
        self.tab_widget.addTab( self.blocked_devices, "Blocked devices")
        self.tab_widget.addTab( self.blocked_apps, "Blocked apps")
        self.tab_widget.addTab(self.blocked_site, "Blocked sites")
        self.tab_widget.addTab( self.NIDS, "NIDS")
        self.tab_widget.addTab(self.HIDS, "HIDS")

        
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)
        
       # self.load_devicetable()
        #self.load_apptable()
        #self.load_sitetable()
        
    """  
    def load_devicetable(self):
        self.devictabletable.setRowCount(0)
    
        query = QSqlQuery("SELECT * FROM DeviceTable")
        row = 0
        while query.next():
            Id = query.value(0)
            Device = query.value(1)
            State = query.value(2)
            Time = query.value(3)
            Date = query.value(4)
        
            self.devicetable.insertRow(row)
            self.devicetable.setItem(row,0,QTableWidgetItem(str(Id)))
            self.devicetable.setItem(row,1,QTableWidgetItem(Device))
            self.devicetable.setItem(row,2,QTableWidgetItem(State))
            self.devicetable.setItem(row,3,QTableWidgetItem(Time))
            self.devicetable.setItem(row,4,QTableWidgetItem(Date))
        
        
            row += 1
        
       
        
        
    def load_apptable(self):
        self.apptable.setRowCount(0)
    
        query = QSqlQuery("SELECT * FROM AppTable")
        row = 0
        while query.next():
            Id = query.value(0)
            App = query.value(1)
            State = query.value(2)
            Time = query.value(3)
            Date = query.value(4)
        
            self.apptable.insertRow(row)
            self.apptable.setItem(row,0,QTableWidgetItem(str(Id)))
            self.apptable.setItem(row,1,QTableWidgetItem(App))
            self.apptable.setItem(row,2,QTableWidgetItem(State))
            self.apptable.setItem(row,3,QTableWidgetItem(Time))
            self.apptable.setItem(row,4,QTableWidgetItem(Date))
        
        
            row += 1
        
        
        
        
    def load_sitetable(self):
        self.sitetable.setRowCount(0)
    
        query = QSqlQuery("SELECT * FROM SiteTable")
        row = 0
        while query.next():
            Id = query.value(0)
            Site = query.value(1)
            State = query.value(2)
            Time = query.value(3)
            Date = query.value(4)
        
            self.sitetable.insertRow(row)
            self.sitetable.setItem(row,0,QTableWidgetItem(str(Id)))
            self.sitetable.setItem(row,1,QTableWidgetItem(Site))
            self.sitetable.setItem(row,2,QTableWidgetItem(State))
            self.sitetable.setItem(row,3,QTableWidgetItem(Time))
            self.sitetable.setItem(row,4,QTableWidgetItem(Date))
        
        
            row += 1
        
    """    
class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self): 
        layout = QVBoxLayout()
        allbutlayout = QHBoxLayout()
        but1layout = QVBoxLayout()
        but2layout = QVBoxLayout()
        but3layout = QVBoxLayout()
        
        report_label = QLabel('Reports')
        self.report_button = QPushButton("0",self)
        #self.report_button.clicked.connect()
        
        but1layout.addWidget(report_label)
        but1layout.addWidget(self.report_button)
        
        
        
        host_label = QLabel('Host intrusions')
        self.host_button = QPushButton("0",self)
        #self.host_button.clicked.connect()
        
        but2layout.addWidget(host_label)
        but2layout.addWidget(self.host_button)
        
        
        network_label = QLabel('Network intrusions')
        self.network_button = QPushButton("0",self)
        #self.network_button.clicked.connect()
        
        but3layout.addWidget(network_label)
        but3layout.addWidget(self.network_button)
        
        
        allbutlayout.addLayout(but1layout)
        allbutlayout.addLayout(but2layout)
        allbutlayout.addLayout(but3layout)
        
        
        self.mixtable = QTableWidget()
        self.mixtable.setColumnCount(5)
        self.mixtable.setHorizontalHeaderLabels(["Id", "Description", "Prediction", "Time", "Date"])
        
        
        layout.addLayout(allbutlayout)
        layout.addWidget(self.mixtable)
        
        self.setLayout(layout)


#database

#database = QSqlDatabase.addDatabase("QSQLITE")
#database.setDatabaseName ("Intrusion.db")
#if not database.open():
 #   QMessageBox.critical(None, "Error","could not open Database")
  #  sys.exit(1)       
    
    
#query = QSqlQuery()
#query.exec_("""
  #          CREATE TABLE IF NOT EXISTS NetworkTable(
   #             Id INTEGER PRIMARY KEY AUTOINCREMENT,
    #            Packet TEXT,
     #           Prediction TEXT,
      #          Time TEXT,
       #         Date TEXT
        #    )
            
         #   """)

#query.exec_("""
 #           CREATE TABLE IF NOT EXISTS HostTable(
  #              Id INTEGER PRIMARY KEY AUTOINCREMENT,
   #             Source TEXT,
    #            Event_ID INTEGER,
     #           General TEXT,
      #          Prediction TEXT,
       #         Time TEXT,
        #        Date TEXT
         #   )
            
          #  """)

#query.exec_("""
 #           CREATE TABLE IF NOT EXISTS DeviceTable(
  #              Id INTEGER PRIMARY KEY AUTOINCREMENT,
   #             Device TEXT,
    #            State TEXT,
     #           time TEXT,
      #          date TEXT
       #     )
            
        #    """)

#query.exec_("""
 #           CREATE TABLE IF NOT EXISTS APPTable(
  #              Id INTEGER PRIMARY KEY AUTOINCREMENT,
   #             App TEXT,
    #            State TEXT,
     #           time TEXT,
      #          date TEXT
       #     )
            
        #    """)


#query.exec_("""
 #           CREATE TABLE IF NOT EXISTS SiteTable(
  #              Id INTEGER PRIMARY KEY AUTOINCREMENT,
   #             Site TEXT,
    #            State TEXT,
     #           time TEXT,
      #          date TEXT
       #     )
            
        #    """)



        
        

        
        
        
        

        
#def add_network(self):
 
 #  time = QTime.currentTime()
  # date = QDate.currentDate()     
   
   #query = QSqlQuery()
   #query.prepare("""
    #             INSERT INTO NetworkTable(Packet, Prediction, Time, Date)
     #            VALUES (?, ?, ?, ?)
      #           """)
   #query.addBindValue()
   #query.addBindValue()
   #query.addBindValue(time)
   #query.addBindValue(date)
   #query.exec_()
   
   
   #self.load_networktable()
   
   

#def add_host(self):
    
 #  time = QTime.currentTime()
  # date = QDate.currentDate()     
   
   
   #query = QSqlQuery()
   #query.prepare("""
    #             INSERT INTO HostTable(Source, Event_ID, General, Prediction, Time, Date)
     #            VALUES (?, ?, ?, ?, ?, ?)
      #           """)
   #query.addBindValue()
   #query.addBindValue()
   #query.addBindValue()
   #query.addBindValue()
   #query.addBindValue(time)
   #query.addBindValue(date)
   #query.exec_()
   
   
  # self.load_hosttable()
   
   
   
#def add_device(self):
    
 #  time = QTime.currentTime()
  # date = QDate.currentDate() 
   #state = "blocked"    
   
   
   #query = QSqlQuery()
   #query.prepare("""
    #             INSERT INTO DeviceTable(Device, State, Time, Date)
     #            VALUES (?, ?, ?, ?)
    #             """)
   #query.addBindValue()
   #query.addBindValue(state)
   #query.addBindValue(time)
   #query.addBindValue(date)
   #query.exec_()
   
   
   #self.load_devicetable()
   
   
#def add_app(self):
    
 #  time = QTime.currentTime()
  # date = QDate.currentDate() 
   #state = "blocked"    
   
   
   #query = QSqlQuery()
   #query.prepare("""
    #             INSERT INTO AppTable(App, State, Time, Date)
     #            VALUES (?, ?, ?, ?)
      #           """)
   #query.addBindValue()
   #query.addBindValue(state)
   #query.addBindValue(time)
   #query.addBindValue(date)
   #query.exec_()
   
   
   #self.load_apptable()
   
   
   
#def add_site(self):
    
 #  time = QTime.currentTime()
  # date = QDate.currentDate()
   #state = "blocked"     
   
   
   #query = QSqlQuery()
   #query.prepare("""
    #             INSERT INTO SiteTable(Site, State, Time, Date)
     #            VALUES (?, ?, ?, ?)
      #           """)
   #query.addBindValue()
   #query.addBindValue(state)
   #query.addBindValue(time)
   #query.addBindValue(date)
   #query.exec_()
   
   
   #self.load_sitetable()
        
"""        
def delete_network(self):
    selected_row = self.networktable.currentRow()
    if selected_row == -1:
        QMessageBox.warning(self,"No Packet Chosen","Please Choose Packet")
        return
    network_id = int(self.networktable.item(selected_row,0).text())
    
    query = QSqlQuery()
    query.prepare("DELETE FROM NetworkTable WHERE Id = ?")
    query.addBindValue(network_id)
    query.exec_()
    
    self.load_networktable()
    
    
def delete_host(self):
    selected_row = self.hosttable.currentRow()
    if selected_row == -1:
        QMessageBox.warning(self,"No Row Chosen","Please Choose Row")
        return
    host_id = int(self.hosttable.item(selected_row,0).text())
    
    query = QSqlQuery()
    query.prepare("DELETE FROM HostTable WHERE Id = ?")
    query.addBindValue(host_id)
    query.exec_()
    
    self.load_hosttable()
"""   


    
    