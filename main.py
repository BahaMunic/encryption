import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.exceptions import InvalidKey
import os
import logging
from datetime import datetime

class ModernEncryptDecryptApp:
    def __init__(self, root):
        self.root = root
        self.setup_logging()
        self.initialize_ui()
        self.setup_styles()
        self.create_widgets()

    def setup_logging(self):
        """Configure logging for the application"""
        logging.basicConfig(
            filename=f'encryption_app_{datetime.now().strftime("%Y%m%d")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def initialize_ui(self):
        """Initialize main UI settings"""
        self.root.title("نظام التشفير المتقدم")
        self.root.geometry("500x320")
        self.root.config(bg="#f0f2f6")
        self.root.resizable(False, False)

    def setup_styles(self):
        """Define application styles"""
        self.styles = {
            'main_font': ("Helvetica", 12),
            'button_color': "#4a90e2",
            'error_color': "#e74c3c",
            'success_color': "#2ecc71",
            'entry_bg': "#ffffff",
            'frame_bg': "#ffffff",
            'label_bg': "#f0f2f6",
            'active_color': "#357ABD",
        }

    def create_widgets(self):
        # Create main frame
        self.main_frame = tk.Frame(self.root, bg=self.styles['label_bg'], padx=10, pady=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # File selection section
        self.create_file_section()

        # Password section
        self.create_password_section()

        # Action buttons
        self.create_action_buttons()

        # Status section
        self.create_status_section()

        # Agency label
        agency_label = tk.Label(self.root, text='تم بواسطة وكالة التحول الرقمي بأمانة منطقة الباحة',
                                justify='center', wraplength=480, bg=self.styles['label_bg'],
                                font=self.styles['main_font'])
        agency_label.pack(side='bottom', pady=(0, 10))

        # Create menu
        self.create_menu()

    def create_menu(self):
        """Create the menu for the application"""
        menu_bar = tk.Menu(self.root)

        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="خروج", command=self.root.quit)
        menu_bar.add_cascade(label="ملف", menu=file_menu)

        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="حول", command=self.show_about)
        help_menu.add_command(label="ترخيص", command=self.show_license)
        menu_bar.add_cascade(label="حول", menu=help_menu)

        self.root.config(menu=menu_bar)

    def show_about(self):
        """Display information about the application"""
        messagebox.showinfo("حول", "برنامج لتشفير وفك تشفير الملفات.\n\n"
                                      "تم تطوير هذا البرنامج بواسطة وكالة التحول الرقمي بأمانة منطقة الباحة.")

    def show_license(self):
        """Display license information"""
        messagebox.showinfo("ترخيص", "هذا البرنامج مرخص بموجب رخصة جنو العمومية العامة الإصدار 2 (GPLv2).\n"
                                      "يمكنك إعادة توزيعه وتعديله وفقًا للشروط الواردة في الرخصة.\n"
                                      "للمزيد من المعلومات، يمكن الاطلاع على تفاصيل التراخيص العمومية بالرابط https://www.gnu.org/licenses/")

    def create_file_section(self):
        file_frame = tk.LabelFrame(self.main_frame, text="اختيار الملف", bg=self.styles['frame_bg'], font=self.styles['main_font'])
        file_frame.pack(fill=tk.X, pady=10)

        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(file_frame, textvariable=self.file_path_var, font=self.styles['main_font'], bg=self.styles['entry_bg'])
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        browse_btn = tk.Button(file_frame, text="تصفح", command=self.browse_file,
                             bg=self.styles['button_color'], fg="white", font=self.styles['main_font'], activebackground=self.styles['active_color'])
        browse_btn.pack(side=tk.RIGHT, padx=5, pady=5)

    def create_password_section(self):
        password_frame = tk.LabelFrame(self.main_frame, text="كلمة المرور", bg=self.styles['frame_bg'], font=self.styles['main_font'])
        password_frame.pack(fill=tk.X, pady=10)

        self.password_entry = tk.Entry(password_frame, show='*', font=self.styles['main_font'], bg=self.styles['entry_bg'])
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        self.confirm_password_entry = tk.Entry(password_frame, show='*', font=self.styles['main_font'], bg=self.styles['entry_bg'])
        self.confirm_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

    def create_action_buttons(self):
        button_frame = tk.Frame(self.main_frame, bg=self.styles['label_bg'])
        button_frame.pack(pady=10)

        encrypt_button = tk.Button(button_frame, text="تشفير", command=self.encrypt_file,
                                    bg=self.styles['button_color'], fg="white", font=self.styles['main_font'], activebackground=self.styles['active_color'])
        encrypt_button.pack(side=tk.LEFT, padx=5)

        decrypt_button = tk.Button(button_frame, text="فك التشفير", command=self.decrypt_file,
                                    bg=self.styles['button_color'], fg="white", font=self.styles['main_font'], activebackground=self.styles['active_color'])
        decrypt_button.pack(side=tk.LEFT, padx=5)

    def create_status_section(self):
        self.status_label = tk.Label(self.main_frame, text="", bg=self.styles['label_bg'], font=self.styles['main_font'])
        self.status_label.pack(pady=10)

    def browse_file(self):
        """Open a file dialog to select a file"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)

    def validate_inputs(self):
        """Validate the user inputs"""
        if not self.file_path_var.get():
            self.handle_error("يرجى اختيار ملف.")
            return False
        if not self.password_entry.get():
            self.handle_error("يرجى إدخال كلمة المرور.")
            return False
        if self.password_entry.get() != self.confirm_password_entry.get():
            self.handle_error("كلمات المرور غير متطابقة.")
            return False
        return True

    def generate_key(self, password, salt, iterations=100000):
        """Generate a key from the password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self):
        """Enhanced encryption method with additional security measures"""
        try:
            if not self.validate_inputs():
                return

            salt = os.urandom(32)  # Increased salt size for better security
            iv = os.urandom(16)
            key = self.generate_key(self.password_entry.get(), salt, iterations=100000)

            input_path = self.file_path_var.get()
            # Save encrypted file with .ebaha extension
            output_path = f"{input_path}.ebaha"

            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                # Write metadata
                f_out.write(salt)
                f_out.write(iv)

                # Setup encryption
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()

                chunk_size = 64 * 1024  # 64KB chunks

                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break

                    if len(chunk) % 16:
                        padder = padding.PKCS7(128).padder()
                        chunk = padder.update(chunk) + padder.finalize()

                    encrypted_chunk = encryptor.update(chunk)
                    f_out.write(encrypted_chunk)

                f_out.write(encryptor.finalize())

            self.update_status("تم تشفير الملف بنجاح!", "success")
            self.logger.info(f"File encrypted successfully: {output_path}")

        except Exception as e:
            self.handle_error(f"فشل في تشفير الملف: {str(e)}")

    def decrypt_file(self):
        """Enhanced decryption method with improved error handling"""
        try:
            if not self.validate_inputs():
                return

            input_path = self.file_path_var.get()
            # Ensure that the input file has the .ebaha extension
            if not input_path.endswith('.ebaha'):
                self.handle_error("يرجى اختيار ملف بتنسيق .ebaha لفك التشفير.")
                return

            output_path = input_path.replace('.ebaha', '')

            # Check if the output file already exists
            if os.path.exists(output_path):
                self.handle_error("الملف الهدف موجود بالفعل. يرجى اختيار اسم مختلف.")
                return

            with open(input_path, 'rb') as f_in:
                salt = f_in.read(32)
                iv = f_in.read(16)

                key = self.generate_key(self.password_entry.get(), salt, iterations=100000)

                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                with open(output_path, 'wb') as f_out:
                    chunk_size = 64 * 1024

                    while True:
                        chunk = f_in.read(chunk_size)
                        if not chunk:
                            break

                        decrypted_chunk = decryptor.update(chunk)
                        f_out.write(decrypted_chunk)

                    f_out.write(decryptor.finalize())

            self.update_status("تم فك تشفير الملف بنجاح!", "success")
            self.logger.info(f"File decrypted successfully: {output_path}")

        except InvalidKey:
            self.handle_error("كلمة المرور غير صحيحة")
        except Exception as e:
            self.handle_error(f"فشل في فك تشفير الملف: {str(e)}")

    def handle_error(self, message):
        """Centralized error handling"""
        self.logger.error(message)
        self.update_status(message, "error")
        messagebox.showerror("خطأ", message)

    def update_status(self, message, status_type):
        """Update status with color coding"""
        color = self.styles['success_color'] if status_type == "success" else self.styles['error_color']
        self.status_label.config(text=message, fg=color)

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernEncryptDecryptApp(root)
    root.mainloop()
