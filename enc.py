import sys, os, hashlib
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit,
    QMessageBox, QProgressBar, QTabWidget, QStatusBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


class FileEncryptor:
    def __init__(self):
        self.block_size = AES.block_size

    def _derive_key_iv(self, password):
        key = hashlib.sha256(password.encode()).digest()
        iv = hashlib.md5(password.encode()).digest()
        return key, iv

    def encrypt_file(self, input_path, password):
        with open(input_path, 'rb') as f:
            data = f.read()
        key, iv = self._derive_key_iv(password)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(data, self.block_size)
        enc_data = cipher.encrypt(padded)
        ext = os.path.splitext(input_path)[1].encode().ljust(8, b'\0')
        return ext + iv + enc_data

    def decrypt_file(self, input_path, password):
        with open(input_path, 'rb') as f:
            data = f.read()
        ext = data[:8].strip(b'\0').decode()
        iv = data[8:24]
        enc = data[24:]
        key, _ = self._derive_key_iv(password)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec_data = unpad(cipher.decrypt(enc), self.block_size)
        return dec_data, ext


class BruteForceThread(QThread):
    progress_update = pyqtSignal(int)
    status_update = pyqtSignal(str)
    success = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, file_path, wordlist_path):
        super().__init__()
        self.file_path = file_path
        self.wordlist_path = wordlist_path
        self.encryptor = FileEncryptor()
        self.running = True

    def run(self):
        try:
            total = sum(1 for _ in open(self.wordlist_path, 'r', errors='ignore'))
            for i, line in enumerate(open(self.wordlist_path, 'r', errors='ignore')):
                if not self.running:
                    break
                password = line.strip()
                self.status_update.emit(f"Trying: {password}")
                try:
                    self.encryptor.decrypt_file(self.file_path, password)
                    self.success.emit(password)
                    break
                except Exception:
                    pass
                self.progress_update.emit(int((i + 1) / total * 100))
            self.status_update.emit("Completed" if self.running else "Stopped")
            self.finished_signal.emit()
        except Exception as e:
            self.status_update.emit(f"Error: {e}")
            self.finished_signal.emit()

    def stop(self):
        self.running = False


class SecureFileApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureFile - AES Encryptor")
        self.resize(900, 600)
        self.apply_theme()
        self.encryptor = FileEncryptor()
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.init_tabs()

    def apply_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #1A103D; }
            QWidget { background-color: #1A103D; color: #FFFFFF; font-family: 'Segoe UI', Arial; }
            
            QTabWidget::pane { 
                border: 2px solid #2B1B5C; 
                border-radius: 8px; 
                background-color: #1A103D; 
            }
            QTabWidget::tab-bar { alignment: center; }
            QTabBar::tab { 
                background-color: #2B1B5C; 
                color: #FFFFFF; 
                padding: 12px 20px; 
                margin: 2px; 
                border: 1px solid #FFD700;
                border-radius: 6px; 
                font-weight: bold;
                min-width: 80px;
            }
            QTabBar::tab:selected { 
                background-color: #FFD700; 
                color: #1A103D; 
            }
            QTabBar::tab:hover { 
                background-color: #FFEA70; 
                color: #1A103D; 
            }
            
            QPushButton { 
                background-color: #FFD700; 
                color: #1A103D; 
                padding: 10px 15px; 
                border: none; 
                border-radius: 6px; 
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover { 
                background-color: #FFEA70; 
                transform: scale(1.02);
            }
            QPushButton:pressed { background-color: #E6C200; }
            QPushButton:disabled { 
                background-color: #2B1B5C; 
                color: #666666; 
            }
            
            QLineEdit, QTextEdit { 
                background-color: #2B1B5C; 
                color: #FFFFFF; 
                border: 2px solid #FFD700; 
                border-radius: 6px; 
                padding: 8px; 
                font-size: 11px;
            }
            QLineEdit:focus, QTextEdit:focus { 
                border-color: #FFEA70; 
                background-color: #3A2A6A; 
            }
            
            QLabel { 
                color: #FFFFFF; 
                font-weight: bold; 
                margin: 5px 0; 
            }
            
            QProgressBar { 
                background-color: #2B1B5C; 
                border: 2px solid #FFD700; 
                border-radius: 8px; 
                text-align: center; 
                height: 25px;
            }
            QProgressBar::chunk { 
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #FFD700, stop:1 #FFEA70); 
                border-radius: 6px; 
            }
            
            QStatusBar { 
                background-color: #2B1B5C; 
                color: #FFD700; 
                border-top: 1px solid #FFD700; 
            }
        """)

    def init_tabs(self):
        # Encrypt Tab
        enc_tab = QWidget()
        enc_layout = QVBoxLayout(enc_tab)
        enc_layout.setSpacing(10)

        self.enc_path = QLineEdit()
        self.enc_path.setReadOnly(True)
        self.enc_path.setPlaceholderText("No file selected...")
        
        enc_browse = QPushButton("📁 Browse File")
        enc_browse.clicked.connect(self.browse_enc)
        
        self.enc_key = QLineEdit()
        self.enc_key.setPlaceholderText("Enter encryption password...")
        self.enc_key.setEchoMode(QLineEdit.EchoMode.Password)
        
        enc_btn = QPushButton("🔒 Encrypt & Save")
        enc_btn.clicked.connect(self.encrypt_file)

        enc_layout.addWidget(QLabel("📄 Select File to Encrypt:"))
        enc_layout.addWidget(self.enc_path)
        enc_layout.addWidget(enc_browse)
        enc_layout.addWidget(QLabel("🗝️ Encryption Password:"))
        enc_layout.addWidget(self.enc_key)
        enc_layout.addWidget(enc_btn)
        enc_layout.addStretch()
        
        self.tabs.addTab(enc_tab, "🔒 Encrypt")

        # Decrypt Tab
        dec_tab = QWidget()
        dec_layout = QVBoxLayout(dec_tab)
        dec_layout.setSpacing(10)

        self.dec_path = QLineEdit()
        self.dec_path.setReadOnly(True)
        self.dec_path.setPlaceholderText("No encrypted file selected...")
        
        dec_browse = QPushButton("📁 Browse Encrypted File")
        dec_browse.clicked.connect(self.browse_dec)
        
        self.dec_key = QLineEdit()
        self.dec_key.setPlaceholderText("Enter decryption password...")
        self.dec_key.setEchoMode(QLineEdit.EchoMode.Password)
        
        dec_btn = QPushButton("🔓 Decrypt & Save")
        dec_btn.clicked.connect(self.decrypt_file)

        dec_layout.addWidget(QLabel("📄 Select Encrypted File:"))
        dec_layout.addWidget(self.dec_path)
        dec_layout.addWidget(dec_browse)
        dec_layout.addWidget(QLabel("🗝️ Decryption Password:"))
        dec_layout.addWidget(self.dec_key)
        dec_layout.addWidget(dec_btn)
        dec_layout.addStretch()
        
        self.tabs.addTab(dec_tab, "🔓 Decrypt")

        # Recovery Tab
        rec_tab = QWidget()
        rec_layout = QVBoxLayout(rec_tab)
        rec_layout.setSpacing(8)

        self.rec_path = QLineEdit()
        self.rec_path.setReadOnly(True)
        self.rec_wordlist = QLineEdit()
        self.rec_wordlist.setReadOnly(True)
        
        rec_file_btn = QPushButton("📁 Browse Encrypted File")
        rec_file_btn.clicked.connect(self.browse_rec_file)
        rec_list_btn = QPushButton("📝 Browse Wordlist")
        rec_list_btn.clicked.connect(self.browse_rec_list)

        self.rec_progress = QProgressBar()
        self.rec_status = QTextEdit()
        self.rec_status.setReadOnly(True)
        self.rec_status.setMaximumHeight(120)
        self.rec_result = QLineEdit()
        self.rec_result.setReadOnly(True)
        self.rec_result.setPlaceholderText("Recovered password will appear here...")

        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("🚀 Start Recovery")
        self.start_btn.clicked.connect(self.start_recovery)
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_recovery)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)

        rec_layout.addWidget(QLabel("📄 Encrypted File:"))
        rec_layout.addWidget(self.rec_path)
        rec_layout.addWidget(rec_file_btn)
        rec_layout.addWidget(QLabel("📝 Password Wordlist:"))
        rec_layout.addWidget(self.rec_wordlist)
        rec_layout.addWidget(rec_list_btn)
        rec_layout.addWidget(self.rec_progress)
        rec_layout.addWidget(QLabel("📊 Status:"))
        rec_layout.addWidget(self.rec_status)
        rec_layout.addWidget(QLabel("🎯 Recovered Password:"))
        rec_layout.addWidget(self.rec_result)
        rec_layout.addLayout(button_layout)
        
        self.tabs.addTab(rec_tab, "🔍 Recovery")

        # Credits Tab
        credits_tab = QWidget()
        credits_layout = QVBoxLayout(credits_tab)
        credits_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        credits_text = """
        🛡️ SecureFile AES Encryptor
        
        👨‍💻 Developer: Hamza Sami
        🎯 Cybersecurity Specialist
        
        📧 Email: programmerhamzasami@gmail.com
        📱 Telegram: @h_s_y
        
        🔒 Advanced AES-256 Encryption
        🔓 Password Recovery Tools
        ⚡ Fast & Secure File Protection
        """
        
        credits_label = QLabel(credits_text)
        credits_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        credits_label.setStyleSheet("font-size: 14px; line-height: 1.6; color: #FFD700;")
        credits_layout.addWidget(credits_label)
        
        self.tabs.addTab(credits_tab, "ℹ️ Credits")

    def browse_enc(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if path: self.enc_path.setText(path)

    def encrypt_file(self):
        file_path, key = self.enc_path.text(), self.enc_key.text()
        if not file_path or not key:
            QMessageBox.warning(self, "Input Error", "Please select file and enter password.")
            return
        try:
            data = self.encryptor.encrypt_file(file_path, key)
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", "", "Encrypted Files (*.enc)")
            if save_path:
                if not save_path.endswith(".enc"): save_path += ".enc"
                with open(save_path, 'wb') as f: f.write(data)
                QMessageBox.information(self, "Success", f"File encrypted successfully!\nSaved: {save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {e}")

    def browse_dec(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File", "", "Encrypted Files (*.enc);;All Files (*)")
        if path: self.dec_path.setText(path)

    def decrypt_file(self):
        file_path, key = self.dec_path.text(), self.dec_key.text()
        if not file_path or not key:
            QMessageBox.warning(self, "Input Error", "Please select file and enter password.")
            return
        try:
            data, ext = self.encryptor.decrypt_file(file_path, key)
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", "", f"Recovered File (*{ext});;All Files (*)")
            if save_path:
                if not save_path.endswith(ext): save_path += ext
                with open(save_path, 'wb') as f: f.write(data)
                QMessageBox.information(self, "Success", f"File decrypted successfully!\nSaved: {save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: Wrong password or corrupted file")

    def browse_rec_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File", "", "Encrypted Files (*.enc);;All Files (*)")
        if path: self.rec_path.setText(path)

    def browse_rec_list(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if path: self.rec_wordlist.setText(path)

    def start_recovery(self):
        file, wordlist = self.rec_path.text(), self.rec_wordlist.text()
        if not file or not wordlist:
            QMessageBox.warning(self, "Input Error", "Please select both encrypted file and wordlist.")
            return
        
        self.brute = BruteForceThread(file, wordlist)
        self.brute.progress_update.connect(self.rec_progress.setValue)
        self.brute.status_update.connect(self.rec_status.append)
        self.brute.success.connect(self.rec_result.setText)
        self.brute.success.connect(lambda p: QMessageBox.information(self, "🎉 Success", f"Password found: {p}"))
        self.brute.finished_signal.connect(lambda: (self.start_btn.setEnabled(True), self.stop_btn.setEnabled(False)))
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.rec_status.clear()
        self.rec_result.clear()
        self.brute.start()

    def stop_recovery(self):
        if hasattr(self, 'brute') and self.brute.isRunning():
            self.brute.stop()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureFileApp()
    window.show()
    sys.exit(app.exec())