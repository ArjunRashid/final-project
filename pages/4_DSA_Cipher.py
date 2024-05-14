import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.exceptions import InvalidSignature

class DSAApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DSA Signature Verification")
        self.init_ui()
        
        # Generate key pair
        self.private_key, self.public_key = self.generate_keypair()

    def init_ui(self):
        layout = QVBoxLayout()

        self.message_label = QLabel("Enter message:")
        layout.addWidget(self.message_label)
        self.message_input = QLineEdit()
        layout.addWidget(self.message_input)

        self.sign_button = QPushButton("Sign")
        self.sign_button.clicked.connect(self.sign_message)
        layout.addWidget(self.sign_button)

        self.signature_label = QLabel("Signature:")
        layout.addWidget(self.signature_label)
        self.signature_output = QLineEdit()
        self.signature_output.setReadOnly(True)
        layout.addWidget(self.signature_output)

        self.verify_label = QLabel("Enter signature to verify:")
        layout.addWidget(self.verify_label)
        self.verify_input = QLineEdit()
        layout.addWidget(self.verify_input)

        self.verify_button = QPushButton("Verify Signature")
        self.verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(self.verify_button)

        self.setLayout(layout)

    def generate_keypair(self):
        private_key = dsa.generate_private_key(key_size=1024, backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_message(self):
        message = self.message_input.text()
        signature = self.private_key.sign(message.encode(), hashes.SHA256())
        self.signature_output.setText(signature.hex())

    def verify_signature(self):
        input_signature = bytes.fromhex(self.verify_input.text())
        message = self.message_input.text()
        try:
            self.public_key.verify(input_signature, message.encode(), hashes.SHA256())
            QMessageBox.information(self, "Verification", "Signature verified successfully!")
        except InvalidSignature:
            QMessageBox.critical(self, "Verification", "Signature verification failed!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DSAApp()
    window.show()
    sys.exit(app.exec_())
