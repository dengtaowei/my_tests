import os
import socket
import subprocess
import sys
import threading
from datetime import datetime

from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QPushButton, QTextEdit, QLabel, QLineEdit, QFileDialog,
                             QWidget, QGroupBox, QCheckBox, QSpinBox)
from PyQt5.QtCore import Qt, pyqtSignal, QObject


class SignalEmitter(QObject):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)


class WiresharkCaptureTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.signal_emitter = SignalEmitter()
        self.signal_emitter.log_signal.connect(self.log_message)
        self.signal_emitter.status_signal.connect(self.update_status)

        self.thread_id_counter = 0
        self.active_threads = {}
        self.server_socket = None
        self.running = False

        self.init_ui()
        self.setWindowTitle("Wireshark Remote Capture Tool")
        self.resize(800, 600)

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()

        # Configuration Group
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout()

        # Wireshark Path
        ws_path_layout = QHBoxLayout()
        ws_path_layout.addWidget(QLabel("Wireshark Path:"))
        self.wireshark_path_edit = QLineEdit(r'C:\Program Files\Wireshark\Wireshark.exe')
        ws_path_layout.addWidget(self.wireshark_path_edit)
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_wireshark)
        ws_path_layout.addWidget(browse_button)
        config_layout.addLayout(ws_path_layout)

        # Output Directory
        out_dir_layout = QHBoxLayout()
        out_dir_layout.addWidget(QLabel("Output Directory:"))
        self.output_dir_edit = QLineEdit(os.getcwd())
        out_dir_layout.addWidget(self.output_dir_edit)
        out_browse_button = QPushButton("Browse...")
        out_browse_button.clicked.connect(self.browse_output_dir)
        out_dir_layout.addWidget(out_browse_button)
        config_layout.addLayout(out_dir_layout)

        # Port Settings
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port:"))
        self.port_spinbox = QSpinBox()
        self.port_spinbox.setRange(1, 65535)
        self.port_spinbox.setValue(12345)
        port_layout.addWidget(self.port_spinbox)
        config_layout.addLayout(port_layout)

        # Auto Save
        self.auto_save_check = QCheckBox("Auto Save PCAP Files")
        self.auto_save_check.setChecked(False)
        config_layout.addWidget(self.auto_save_check)

        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)

        # Control Buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Server")
        self.start_button.clicked.connect(self.toggle_server)
        button_layout.addWidget(self.start_button)

        self.clear_button = QPushButton("Clear Log")
        self.clear_button.clicked.connect(self.clear_log)
        button_layout.addWidget(self.clear_button)

        main_layout.addLayout(button_layout)

        # Log Display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        main_layout.addWidget(self.log_display)

        # Status Bar
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

    def browse_wireshark(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wireshark Executable",
            "C:\\Program Files", "Executable (*.exe)"
        )
        if path:
            self.wireshark_path_edit.setText(path)

    def browse_output_dir(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory",
            self.output_dir_edit.text()
        )
        if path:
            self.output_dir_edit.setText(path)

    def log_message(self, message):
        self.log_display.append(message)

    def update_status(self, message):
        self.status_label.setText(message)

    def clear_log(self):
        self.log_display.clear()

    def toggle_server(self):
        if self.running:
            self.stop_server()
        else:
            self.start_server()

    def start_server(self):
        if not os.path.exists(self.wireshark_path_edit.text()):
            self.signal_emitter.log_signal.emit("Error: Wireshark path is invalid!")
            return

        if not os.path.exists(self.output_dir_edit.text()):
            try:
                os.makedirs(self.output_dir_edit.text(), exist_ok=True)
                self.signal_emitter.log_signal.emit(f"Created directory: {self.output_dir_edit.text()}")
            except Exception as e:
                self.signal_emitter.log_signal.emit(f"Error creating directory: {str(e)}")
                return

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind(('', self.port_spinbox.value()))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1)

            self.running = True
            self.start_button.setText("Stop Server")
            self.signal_emitter.log_signal.emit(f"Server started on port {self.port_spinbox.value()}")
            self.signal_emitter.status_signal.emit("Running")

            # Start server thread
            server_thread = threading.Thread(target=self.run_server, daemon=True)
            server_thread.start()

        except Exception as e:
            self.signal_emitter.log_signal.emit(f"Error starting server: {str(e)}")
            self.server_socket.close()
            self.server_socket = None

    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None

        self.start_button.setText("Start Server")
        self.signal_emitter.log_signal.emit("Server stopped")
        self.signal_emitter.status_signal.emit("Stopped")

    def run_server(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                current_id = self.thread_id_counter
                self.thread_id_counter += 1

                self.signal_emitter.log_signal.emit(
                    f"Accepted connection from {addr[0]}:{addr[1]} (Thread ID: {current_id})")

                # Start client thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr, current_id),
                    daemon=True
                )
                self.active_threads[current_id] = client_thread
                client_thread.start()

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Only log if we didn't intentionally stop
                    self.signal_emitter.log_signal.emit(f"Server error: {str(e)}")
                break

    def handle_client(self, conn, addr, thread_id):
        self.signal_emitter.log_signal.emit(f"[{thread_id}] Handling connection from {addr[0]}:{addr[1]}")

        wireshark_params = [self.wireshark_path_edit.text(), '-k', '-i', '-']
        if self.auto_save_check.isChecked():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.output_dir_edit.text(), f"{timestamp}.pcap")
            wireshark_params += ['-w', output_file]

        try:
            wireshark = subprocess.Popen(
                wireshark_params,
                stdin=subprocess.PIPE,
                bufsize=0,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            )

            while True:
                data = conn.recv(4096)
                if not data:
                    break
                wireshark.stdin.write(data)
                wireshark.stdin.flush()

        except (BrokenPipeError, ConnectionResetError) as e:
            self.signal_emitter.log_signal.emit(f"[{thread_id}] Connection error: {str(e)}")
        except Exception as e:
            self.signal_emitter.log_signal.emit(f"[{thread_id}] Unexpected error: {str(e)}")
        finally:
            self.signal_emitter.log_signal.emit(f"[{thread_id}] Closing connection from {addr[0]}:{addr[1]}")
            if 'wireshark' in locals() and not wireshark.stdin.closed:
                wireshark.stdin.close()
            conn.close()
            if thread_id in self.active_threads:
                del self.active_threads[thread_id]

            self.signal_emitter.log_signal.emit(f"[{thread_id}] Thread exit")

    def closeEvent(self, event):
        if self.running:
            self.stop_server()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WiresharkCaptureTool()
    window.show()
    sys.exit(app.exec_())