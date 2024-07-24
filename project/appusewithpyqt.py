import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QPushButton, QWidget, QFrame, QStackedWidget
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt, QTimer
import psutil
from PIL import Image
import win32gui
import win32api
import win32con
import win32process
import os
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# Function to get the icon of a process based on its PID
def get_process_icon(pid):
    try:
         # Open the process to query its information and memory
        handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
          # Get the executable path of the process
        executable_path = win32process.GetModuleFileNameEx(handle, 0)
         # Close the process handle
        win32api.CloseHandle(handle)
        
        # Check if the executable path is valid
        if not os.path.isfile(executable_path):
            print(f"Executable path not found: {executable_path}")
            return None
        
        # Extract large and small icons from the executable
        large, small = win32gui.ExtractIconEx(executable_path, 0)
        if small:
            return small[0]
        elif large:
            return large[0]
        else:
            return None
    except Exception as e:
        print(f"Failed to get icon for pid {pid}: {e}")
        return None

# Function to convert icon handle to a QIcon
def get_icon_image(icon_handle):
    if icon_handle:
        
         # Create a device context compatible with the screen
        hdc = win32gui.CreateCompatibleDC(0)
        
         # Create a bitmap compatible with the device context
        bmp = win32gui.CreateCompatibleBitmap(hdc, 32, 32)
         # Select the bitmap into the device context
        hdc_old = win32gui.SelectObject(hdc, bmp)
        
         # Draw the icon into the device context
        win32gui.DrawIconEx(hdc, 0, 0, icon_handle, 32, 32, 0, 0, win32con.DI_NORMAL)
         # Get the bitmap bits
        bmpstr = win32gui.GetBitmapBits(bmp, True)
        # Create an image from the bitmap bits
        image = Image.frombuffer("RGBA", (32, 32), bmpstr, "raw", "BGRA", 0, 1)
         # Restore the original device context
        win32gui.SelectObject(hdc, hdc_old)
        
         # Delete the bitmap and device context
        win32gui.DeleteObject(bmp)
        win32gui.DeleteDC(hdc)
        
         # Convert the image to QIcon and return it
        return QIcon(QPixmap.fromImage(image.toqimage()))
    else:
        return None

# Function to check if a process has a visible window
def has_visible_window(pid):
    def callback(hwnd, found_pids):
         # Get the process ID for the window
        _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
         # Check if the window belongs to the process and is visible
        if found_pid == pid and win32gui.IsWindowVisible(hwnd):
            found_pids.append(hwnd)

    found_pids = []
    # Enumerate all windows and apply the callback function
    win32gui.EnumWindows(callback, found_pids)
    return len(found_pids) > 0

# Main application class
class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Running Applications and Background Processes")

        self.main_widget = QWidget(self)
        self.setCentralWidget(self.main_widget)
        self.layout = QVBoxLayout(self.main_widget)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(7)
        self.tree.setHeaderLabels(["Icon", "PID", "Name", "Status", "CPU (%)", "Memory (%)", "Type"])
        self.layout.addWidget(self.tree)

        self.refresh_button = QPushButton("Refresh", self)
        self.refresh_button.clicked.connect(self.update_process_list)
        self.layout.addWidget(self.refresh_button)

        self.images = {}
        self.update_process_list()
        
        
        # Variables for selected process and resource usage data
        self.selected_pid = None
        self.cpu_data = []
        self.memory_data = []
        self.time_data = []
        
        
        # Matplotlib figure and canvas for plotting
        self.figure, self.ax = plt.subplots(2, 1, figsize=(8, 6))
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(self.canvas)
        
        # Connect tree selection change to handler
        self.tree.itemSelectionChanged.connect(self.on_tree_select)

    def update_process_list(self):
        self.tree.clear()
        processes = sorted(psutil.process_iter(['pid', 'name', 'status']), key=lambda p: p.info['name'])
        
        
         # Preload CPU usage for processes
        for proc in processes:
            try:
                proc.cpu_percent(interval=None)
            except Exception as e:
                continue

        time.sleep(1)

        for proc in processes:
            try:
                cpu_usage = proc.cpu_percent(interval=None)
                memory_usage = proc.memory_percent()
                icon_handle = get_process_icon(proc.info['pid'])
                icon_image = get_icon_image(icon_handle)
                process_type = "Application" if has_visible_window(proc.info['pid']) else "Background"

                item = QTreeWidgetItem(self.tree, ["", str(proc.info['pid']), proc.info['name'], proc.info['status'], str(cpu_usage), str(memory_usage), process_type])

                if icon_image:
                    item.setIcon(0, icon_image)
                    self.images[item] = icon_image
            except Exception as e:
                continue

    def on_tree_select(self):
        selected_items = self.tree.selectedItems()
        if selected_items:
            item = selected_items[0]
            self.selected_pid = int(item.text(1))
            self.cpu_data = []
            self.memory_data = []
            self.time_data = []
            self.update_graph()

    def update_graph(self):
        if self.selected_pid is None:
            return

        try:
            proc = psutil.Process(self.selected_pid)
            self.cpu_data.append(proc.cpu_percent(interval=1))
            self.memory_data.append(proc.memory_percent())
            self.time_data.append(time.time())

            self.ax[0].cla()
            self.ax[0].plot(self.time_data, self.cpu_data, label='CPU Usage (%)')
            self.ax[0].set_ylabel('CPU Usage (%)')
            self.ax[0].legend()

            self.ax[1].cla()
            self.ax[1].plot(self.time_data, self.memory_data, label='Memory Usage (%)')
            self.ax[1].set_ylabel('Memory Usage (%)')
            self.ax[1].legend()

            self.canvas.draw()

            QTimer.singleShot(1000, self.update_graph)
        except psutil.NoSuchProcess:
            self.selected_pid = None
            self.update_process_list()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = App()
    main_window.show()
    sys.exit(app.exec_())
