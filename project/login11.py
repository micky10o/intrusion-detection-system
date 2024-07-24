import os
import sys
import subprocess
import ctypes
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTabWidget, QStackedWidget, QFrame, QListWidget, QMessageBox, QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
import scapy.all as scp
import scapy.arch.windows as scpwinarch
import win32com.client
import winreg
from NIDSpyqt import NIDS
from appusewithpyqt import App
from generatesyslogpyqt import RealTimeLogViewer
from dashandreport import Report, Dashboard


# Constants for broadcasting a message to all windows and notifying about setting changes

HWND_BROADCAST = 0xFFFF
WM_SETTINGCHANGE = 0x001A

# redirect site 
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
REDIRECT_IP = "127.0.0.1"


 

class LoginPage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        header = QLabel('Login')
        header.setFont(QFont('Arial', 20))
        header.setAlignment(Qt.AlignCenter)

        username_layout = QHBoxLayout()
        username_label = QLabel('Username:')
        self.username_input = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)

        password_layout = QHBoxLayout()
        password_label = QLabel('Password:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)

        login_button = QPushButton('Login')
        login_button.clicked.connect(self.handle_login)

        layout.addWidget(header)
        layout.addLayout(username_layout)
        layout.addLayout(password_layout)
        layout.addWidget(login_button, alignment=Qt.AlignCenter)

        self.setLayout(layout)

    def handle_login(self):
        #handle login logic
        username = self.username_input.text()
        password = self.password_input.text()
        if username == "admin" and password == "admin":
            self.stacked_widget.setCurrentIndex(1)
            
        else:
            print("Invalid credentials")
            
            

        
        

class USBDevicesPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        
        # create and add device list
        self.device_list = QListWidget()
        layout.addWidget(self.device_list)
        self.refresh_button = QPushButton('Refresh Devices')
        self.refresh_button.clicked.connect(self.refresh_devices)
        layout.addWidget(self.refresh_button)
        
        
        # create and add block button 
        self.block_button = QPushButton('Block Selected Device')
        self.block_button.clicked.connect(self.block_device)
        layout.addWidget(self.block_button)

        # Create and add unblock button
        self.unblock_button = QPushButton('Unblock Selected Device')
        self.unblock_button.clicked.connect(self.unblock_device)
        layout.addWidget(self.unblock_button)

        self.setLayout(layout)
        self.refresh_devices()

    def refresh_devices(self):
         # Refresh the list of USB devices
        self.device_list.clear()
        self.devices = self.get_usb_devices()
        for device in self.devices:
            item = QListWidgetItem(f"{device['Description']} ({device['DeviceID']})")
            self.device_list.addItem(item)

    def get_usb_devices(self):
        # Get the list of USB devices
        c = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        conn = c.ConnectServer(".", "root\\cimv2")
        usb_devices = conn.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'")
        devices = [{"DeviceID": dev.DeviceID, "Description": dev.Description} for dev in usb_devices]
        return devices

    def block_device(self):
        # Block the selected USB device

        selected_items = self.device_list.selectedItems()
        if not selected_items:
            QMessageBox.critical(self, "Error", "No device selected")
            return
        device_text = selected_items[0].text()
        device_id = device_text.split('(')[-1][:-1]
        self.change_device_state(device_id, disable=True)
        QMessageBox.information(self, "Success", "Device blocked successfully")

    def unblock_device(self):
        # Unblock the selected USB device
        selected_items = self.device_list.selectedItems()
        if not selected_items:
            QMessageBox.critical(self, "Error", "No device selected")
            return
        device_text = selected_items[0].text()
        device_id = device_text.split('(')[-1][:-1]
        self.change_device_state(device_id, disable=False)
        QMessageBox.information(self, "Success", "Device unblocked successfully")

    def change_device_state(self, device_id, disable=True):
         # Change the state of the USB device
        action = "disable" if disable else "enable"
        try:
            pnputil_path = "C:\\Windows\\System32\\pnputil.exe"
            if action == "disable":
                command = f'{pnputil_path} /disable-device "{device_id}"'
            else:
                command = f'{pnputil_path} /enable-device "{device_id}"'
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                raise Exception(result.stderr)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to change device state: {e}")

class BlockAppsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
          # Create and add app list box
        self.app_listbox = QListWidget()
        layout.addWidget(self.app_listbox)
        
        # Create and add block button
        self.block_button = QPushButton('Block Selected App')
        self.block_button.clicked.connect(self.block_application)
        layout.addWidget(self.block_button)

        self.unblock_button = QPushButton('Unblock Selected App')
        self.unblock_button.clicked.connect(self.unblock_application)
        layout.addWidget(self.unblock_button)

        self.setLayout(layout)
        self.refresh_applications()

    def refresh_applications(self):
         # Refresh the list of installed applications
        self.app_listbox.clear()
        self.applications = self.get_installed_applications()
        for app in self.applications:
            item = QListWidgetItem(app)
            self.app_listbox.addItem(item)

    def get_installed_applications(self):
         # Get the list of installed applications
        return ["notepad.exe", "calculator.exe", "paint.exe", "Wireshark.exe", "chrome.exe", "clock.exe", "photos.exe"]

    def block_application(self):
        # Block the selected application
        selected_items = self.app_listbox.selectedItems()
        if not selected_items:
            QMessageBox.critical(self, "Error", "No application selected")
            return
        application = selected_items[0].text()
        self.add_to_blocked_apps(application)
        QMessageBox.information(self, "Success", f"Application {application} blocked successfully")

    def unblock_application(self):
         # Unblock the selected application
        selected_items = self.app_listbox.selectedItems()
        if not selected_items:
            QMessageBox.critical(self, "Error", "No application selected")
            return
        application = selected_items[0].text()
        self.remove_from_blocked_apps(application)
        QMessageBox.information(self, "Success", f"Application {application} unblocked successfully")

    def add_to_blocked_apps(self, application):
        # Add the application to the blocked list
        try:
            if not is_admin():
                run_as_admin()
                return
            # Open or create the key for DisallowRun
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", 0, winreg.KEY_WRITE)
            disallow_run_key = winreg.CreateKey(key, "DisallowRun")
            
            # Write the application name to DisallowRun
            winreg.SetValueEx(disallow_run_key, application, 0, winreg.REG_SZ, application)
            
            #close the keys
            winreg.CloseKey(disallow_run_key)
            winreg.CloseKey(key)
            
            #notify the system of changes
            ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 'PolicySettings')
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to block application: {e}")

    def remove_from_blocked_apps(self, application):
        # Remove the application from the blocked list
        try:
            if not is_admin():
                run_as_admin()
                return
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", 0, winreg.KEY_READ | winreg.KEY_WRITE)
            
            #search for application and delete its value
            count = 0
            found = False
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, count)
                    if value == application:
                        winreg.DeleteValue(key, name)
                        found = True
                        break
                    count += 1
                except OSError as e:
                    if e.errno == 259:
                        break
                    else:
                        QMessageBox.critical(self, "Error", f"Failed to unblock application: {e}")
                        return
                    
            winreg.CloseKey(key)
            
            if not found:
                QMessageBox.information(self, "Info", f"Application {application} was not found in the blocked list.")
                return
            ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 'PolicySettings')
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to unblock application: {e}")


class WebsiteBlock(QWidget):
   def __init__(self):
        super().__init__()
        self.init_ui()
        
        
   def init_ui(self): 
     
     self.layout = QVBoxLayout()
     self.setLayout(self.layout)

     self.website_listbox = QListWidget(self)
     self.layout.addWidget(self.website_listbox)

     self.website_entry = QLineEdit(self)
     self.layout.addWidget(self.website_entry)

     self.block_button = QPushButton("Block Website", self)
     self.block_button.clicked.connect(self.block_website)
     self.layout.addWidget(self.block_button)

     self.unblock_button = QPushButton("Unblock Website", self)
     self.unblock_button.clicked.connect(self.unblock_website)
     self.layout.addWidget(self.unblock_button)

     self.refresh_websites()

   def refresh_websites(self):
        self.website_listbox.clear()
        blocked_websites = self.get_blocked_websites()
        for website in blocked_websites:
            self.website_listbox.addItem(website)

   def get_blocked_websites(self):
        blocked_websites = []
        try:
            with open(HOSTS_PATH, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    if line.startswith(REDIRECT_IP):
                        blocked_websites.append(line.split()[1])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read hosts file: {e}")
        return blocked_websites

   def block_website(self):
        website = self.website_entry.text().strip()
        if not website:
            QMessageBox.critical(self, "Error", "No website entered")
            return
        if not self.is_valid_website(website):
            QMessageBox.critical(self, "Error", "Invalid website format")
            return
        try:
            if not is_admin():
                run_as_admin()
                return
            with open(HOSTS_PATH, 'a') as file:
                file.write(f"{REDIRECT_IP} {website}\n")
            QMessageBox.information(self, "Success", f"Website {website} blocked successfully")
            self.refresh_websites()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to block website: {e}")

   def unblock_website(self):
        selected_item = self.website_listbox.currentItem()
        if not selected_item:
            QMessageBox.critical(self, "Error", "No website selected")
            return
        website = selected_item.text()
        try:
            if not is_admin():
                run_as_admin()
                return
            with open(HOSTS_PATH, 'r') as file:
                lines = file.readlines()
            with open(HOSTS_PATH, 'w') as file:
                for line in lines:
                    if not line.startswith(f"{REDIRECT_IP} {website}"):
                        file.write(line)
            QMessageBox.information(self, "Success", f"Website {website} unblocked successfully")
            self.refresh_websites()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to unblock website: {e}")

   def is_valid_website(self, website):
        return "." in website and " " not in website

     

class Rulespage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.tab_widget = QTabWidget()
        
        self.usb_tab = USBDevicesPage()
        self.block_apps_tab = BlockAppsPage()
        self.block_site_tab = WebsiteBlock()
        
        self.tab_widget.addTab(self.usb_tab, "USB Devices")
        self.tab_widget.addTab(self.block_apps_tab, "Block Apps")
        self.tab_widget.addTab(self.block_site_tab, "Block Site")
        
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)

class WelcomePage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout()

        # Sidebar
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setAlignment(Qt.AlignTop)
        buttons = ['Dashboard', 'NIDS', 'HIDS', 'Block Intrusion', 'App Analysis', 'Report', 'Logout']
        for button_text in buttons:
            button = QPushButton(button_text)
            button.setObjectName(button_text.lower())
            button.setCheckable(True)
            button.clicked.connect(self.button_clicked)
            sidebar_layout.addWidget(button)

        sidebar = QFrame()
        sidebar.setLayout(sidebar_layout)
        sidebar.setFrameShape(QFrame.StyledPanel)
        sidebar.setFixedWidth(150)

        # Main content area
        self.content_stack = QStackedWidget()
        self.pages = {}
        for button_text in buttons:
            if button_text == 'NIDS':
                page = NIDS()
            elif button_text == 'Block Intrusion':
                page = Rulespage()
                
            elif button_text == 'App Analysis':
                page = App()
            elif button_text == 'HIDS':
                page = RealTimeLogViewer()
                
            elif button_text == 'Report':
                page = Report()
                
            elif button_text == 'Dashboard':
                page = Dashboard()
            
            else:
                page = QLabel(button_text)
                page.setAlignment(Qt.AlignCenter)
                page.setFont(QFont('Arial', 20))
            self.pages[button_text] = page
            self.content_stack.addWidget(page)

        main_content = QFrame()
        main_content.setObjectName("main_content")
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.content_stack)
        main_content.setLayout(main_layout)

        layout.addWidget(sidebar)
        layout.addWidget(main_content)
        self.setLayout(layout)

        # Set stylesheet
        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
            }
            QLabel {
                color: #333;
            }
            QLineEdit {
                border: 2px solid #ccc;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton {
                background-color: #d3d3d3;
                color: black;
                border: none;
                border-radius: 5px;
                padding: 10px;
                cursor: pointer;
                margin: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #b0b0b0;
            }
            QPushButton:pressed, QPushButton:checked {
                background-color: #a0a0a0;
            }
            QPushButton#logout {
                background-color: #d3d3d3;
            }
            QPushButton#logout:hover {
                background-color: #b0b0b0;
            }
            QPushButton#logout:pressed, QPushButton#logout:checked {
                background-color: #a0a0a0;
            }
            QFrame {
                background-color: #d3d3d3;
                border-radius: 15px;
            }
            QFrame#main_content {
                background-color: #ffffff;
                border-radius: 15px;
            }
        """)

    def button_clicked(self):
        button = self.sender()
        if button:
            self.content_stack.setCurrentWidget(self.pages[button.text()])
            button.setChecked(True)
            for btn in self.findChildren(QPushButton):
                if btn != button:
                    btn.setChecked(False)
            if button.text() == 'Logout':
                self.stacked_widget.setCurrentIndex(0)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Login App')
        self.setGeometry(100, 100, 800, 600)

        self.stacked_widget = QStackedWidget()
        self.login_page = LoginPage(self.stacked_widget)
        self.welcome_page = WelcomePage(self.stacked_widget)

        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.welcome_page)

        layout = QVBoxLayout()
        layout.addWidget(self.stacked_widget)
        self.setLayout(layout)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([script] + sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)

def main():
    if not is_admin():
        run_as_admin()
    else:
        app = QApplication(sys.argv)
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec_())

if __name__ == '__main__':
    main()
