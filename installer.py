import os
import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import filedialog
from tkinter import ttk
from pathlib import Path
import paramiko
import threading
import time
import webbrowser


DEFAULT_XAMPP_URL = "https://sourceforge.net/projects/xampp/files/XAMPP%20Linux/8.0.30/xampp-linux-x64-8.0.30-0-installer.run/download"
XAMPP_FILENAME = "xampp-installer.run"

def log_status(message):
    output_box.insert(tk.END, message + "\n")
    output_box.see(tk.END)
    root.update_idletasks()

def get_ssh_client():
    username = username_entry.get()
    ip = ip_entry.get()
    password = password_entry.get()

    if not username or not ip or not password:
        messagebox.showwarning("Input Missing", "Please fill in username, IP, and password.")
        return None, None, None

    try:
        log_status("Connecting to remote server...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)
        log_status("✅ Connection established.")
        return client, username, password
    except Exception as e:
        messagebox.showerror("SSH Error", str(e))
        log_status(f"Connection error: {e}")
        return None, None, None

def install_apache_and_wget():
    def task():
        client, username, password = get_ssh_client()
        if client is None:
            return

        log_status("Installing Apache and wget...")
        #stdin, stdout, stderr = client.exec_command("sudo apt update && sudo apt install -y apache2 wget", get_pty=True)
        stdin, stdout, stderr = client.exec_command("sudo apt update && wget", get_pty=True)
        stdin.write(password + "\n")
        stdin.flush()
        stdout.channel.recv_exit_status()

        #log_status("✅ Apache and wget installation complete.")
        log_status("✅ Downloading of XAMPP from source complete.")

        client.close()

    threading.Thread(target=task, daemon=True).start()

def download_xampp():
    def task():
        client, username, password = get_ssh_client()
        if client is None:
            return

        # Check if file already exists
        log_status("Checking if XAMPP installer already exists...")
        stdin, stdout, stderr = client.exec_command(f"test -f {XAMPP_FILENAME} && echo 'exists' || echo 'missing'")
        result = stdout.read().decode().strip()

        if result == "exists":
            log_status("✅ XAMPP installer already exists. Skipping download.")
        else:
            xampp_url = xampp_url_entry.get() or DEFAULT_XAMPP_URL
            log_status("Starting XAMPP download...")
            stdin, stdout, stderr = client.exec_command(f"wget -O {XAMPP_FILENAME} \"{xampp_url}\"", get_pty=True)

            while not stdout.channel.exit_status_ready():
                log_status("Downloading... (please wait)")
                time.sleep(3)

            stderr_output = stderr.read().decode()
            if "ERROR" in stderr_output or "failed" in stderr_output.lower():
                messagebox.showerror("Download Error", stderr_output)
                log_status("❌ Download failed.")
            else:
                log_status("✅ XAMPP download completed.")

        client.close()

    threading.Thread(target=task, daemon=True).start()

def make_executable_and_run():
    def task():
        client, username, password = get_ssh_client()
        if client is None:
            return

        log_status("Making installer executable...")
        stdin, stdout, stderr = client.exec_command(f"chmod +x {XAMPP_FILENAME}")
        stdout.channel.recv_exit_status()

        log_status("Running XAMPP installer in unattended mode...")

        stdin, stdout, stderr = client.exec_command(f"sudo ./{XAMPP_FILENAME} --mode unattended", get_pty=True)
        stdin.write(password + "\n")
        stdin.flush()

        # Stream real-time output
        while not stdout.channel.exit_status_ready():
            if stdout.channel.recv_ready():
                output = stdout.channel.recv(1024).decode()
                log_status(output.strip())
            if stderr.channel.recv_stderr_ready():
                err = stderr.channel.recv_stderr(1024).decode()
                log_status("⚠️ " + err.strip())
            time.sleep(1)

        # Final cleanup output
        stdout_output = stdout.read().decode().strip()
        stderr_output = stderr.read().decode().strip()

        if stdout_output:
            log_status(stdout_output)
        if stderr_output:
            log_status("⚠️ " + stderr_output)

        log_status("✅ XAMPP installer finished.")
        log_status("Verifying XAMPP installation...")

        stdin, stdout, stderr = client.exec_command("ls /opt/lampp")
        files = stdout.read().decode().strip()

        if files:
            log_status("✅ XAMPP appears to be installed. Contents of /opt/lampp:")
            log_status(files)
        else:
            log_status("⚠️ /opt/lampp is missing. Installation may have failed or been skipped.")


    threading.Thread(target=task, daemon=True).start()

def check_services_status():
    def task():
        client, username, password = get_ssh_client()
        if client is None:
            return

        log_status("🔍 Checking XAMPP (LAMP) service status...")

        stdin, stdout, stderr = client.exec_command("sudo /opt/lampp/lampp status", get_pty=True)
        stdin.write(password + "\n")
        stdin.flush()

        output = stdout.read().decode()
        if "running" in output:
            log_status("✅ XAMPP Status:\n" + output)
        else:
            log_status("⚠️ Some XAMPP services may not be running:\n" + output)

        client.close()

    threading.Thread(target=task, daemon=True).start()


def start_xampp():
    def task():
        client, username, password = get_ssh_client()
        if client is None:
            return

        log_status("Starting XAMPP services...")

        stdin, stdout, stderr = client.exec_command("sudo /opt/lampp/lampp start", get_pty=True)
        stdin.write(password + "\n")
        stdin.flush()
        output = stdout.read().decode()
        log_status(output)

        client.close()

    threading.Thread(target=task, daemon=True).start()


def fix_phpmyadmin_access():
    def task():
        client, username, password = get_ssh_client()
        if client is None:
            return

        log_status("Editing httpd-xampp.conf to allow remote access to phpMyAdmin...")

        # Step 1: Update httpd-xampp.conf
        command = f"sudo sed -i 's/Require local/Require all granted/' /opt/lampp/etc/extra/httpd-xampp.conf"
        stdin, stdout, stderr = client.exec_command(command, get_pty=True)
        stdin.write(password + "\n")
        stdin.flush()
        stdout.channel.recv_exit_status()
        log_status("✅ Updated phpMyAdmin access permissions.")

        # Step 2: Update phpMyAdmin auth_type to 'cookie'
        log_status("Securing phpMyAdmin: setting auth_type to 'cookie'...")

        secure_auth_cmd = (
            "if grep -q \"\\$cfg\\['Servers'\\]\\[\\$i\\]\\['auth_type'\\]\" /opt/lampp/phpmyadmin/config.inc.php; then "
            "sudo sed -i \"s/\\$cfg\\['Servers'\\]\\[\\$i\\]\\['auth_type'\\].*/\\$cfg['Servers'][$i]['auth_type'] = 'cookie';/\" "
            "/opt/lampp/phpmyadmin/config.inc.php; "
            "else echo \"\\$cfg['Servers'][$i]['auth_type'] = 'cookie';\" | sudo tee -a /opt/lampp/phpmyadmin/config.inc.php > /dev/null; "
            "fi"
        )

        stdin, stdout, stderr = client.exec_command(secure_auth_cmd, get_pty=True)
        stdin.write(password + "\n")
        stdin.flush()
        stdout.channel.recv_exit_status()
        log_status("✅ phpMyAdmin will now ask for username & password (cookie auth).")

        # Step 3: Restart XAMPP
        log_status("Restarting XAMPP...")
        stdin, stdout, stderr = client.exec_command("sudo /opt/lampp/lampp restart", get_pty=True)
        stdin.write(password + "\n")
        stdin.flush()
        output = stdout.read().decode()
        log_status(output)

        log_status("✅ XAMPP restarted and secured.")
        client.close()

    threading.Thread(target=task, daemon=True).start()

def open_phpmyadmin():
    ip = ip_entry.get().strip()
    if not ip:
        messagebox.showwarning("Missing IP", "Please enter the server IP address.")
        return
    url = f"http://{ip}/phpmyadmin"
    log_status(f"🌐 Opening {url} in browser...")
    webbrowser.open(url)

def set_mysql_root_password():
    root_pass = simpledialog.askstring("Set Root Password", "Enter new MySQL root password:", show='*', parent=root)
    if not root_pass:
        log_status("⚠️ No password entered. Skipping root password setup.")
        return

    def task():
        client, username, password = get_ssh_client()
        if client is None:
            return

        log_status("🔐 Securing MySQL root account...")

        # Secure MySQL with the entered password
        command = f"""sudo /opt/lampp/bin/mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '{root_pass}'; FLUSH PRIVILEGES;" """
        stdin, stdout, stderr = client.exec_command(command, get_pty=True)
        stdin.write(password + "\n")
        stdin.flush()

        stdout.channel.recv_exit_status()
        err = stderr.read().decode().strip()
        if err:
            log_status(f"❌ Failed to set password: {err}")
        else:
            log_status("✅ MySQL root password updated successfully.")

        client.close()

    threading.Thread(target=task, daemon=True).start()

def select_sql_file():
    file_path = filedialog.askopenfilename(filetypes=[("SQL files", "*.sql")])
    if file_path:
        sql_file_path.set(file_path)
        log_status(f"📂 Selected SQL file: {file_path}")

def import_sql_to_mysql():
    def prompt_and_start_import():
        local_file = sql_file_path.get()
        if not local_file:
            messagebox.showwarning("No File", "Please select a SQL file first.")
            return

        # Prompt dialogs on main thread
        db_name = simpledialog.askstring("Database", "Enter target database name:", parent=root)
        if not db_name:
            return
        mysql_root_password = simpledialog.askstring("MySQL Root Password", "Enter MySQL root password:", show='*', parent=root)
        if not mysql_root_password:
            return

        # Proceed in background thread
        threading.Thread(
            target=do_import_sql,
            args=(local_file, db_name, mysql_root_password),
            daemon=True
        ).start()

    def do_import_sql(local_file, db_name, mysql_root_password):
        client, username, password = get_ssh_client()
        if client is None:
            return

        import os
        remote_path = f"/tmp/{os.path.basename(local_file)}"
        log_status(f"📤 Uploading {local_file} to {remote_path} on server...")

        sftp = client.open_sftp()
        sftp.put(local_file, remote_path)
        sftp.close()

        log_status("✅ Upload complete.")

        # Step 1: Create DB if it doesn't exist
        log_status(f"📦 Ensuring database '{db_name}' exists...")
        create_db_command = f"/opt/lampp/bin/mysql -u root -p'{mysql_root_password}' -e \"CREATE DATABASE IF NOT EXISTS {db_name};\""
        stdin, stdout, stderr = client.exec_command(create_db_command)
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            log_status(f"❌ Failed to create database '{db_name}'. Check credentials or permissions.")
            client.close()
            return

        log_status(f"✅ Database '{db_name}' is ready. Importing SQL...")

        # Step 2: Import SQL file
        import_command = f"/opt/lampp/bin/mysql -u root -p'{mysql_root_password}' {db_name} < {remote_path}"
        stdin, stdout, stderr = client.exec_command(import_command)
        exit_code = stdout.channel.recv_exit_status()

        if exit_code == 0:
            log_status("✅ SQL import successful.")
        else:
            err = stderr.read().decode()
            log_status(f"❌ Import failed:\n{err}")

        client.close()

    # Schedule prompt on main thread
    root.after(0, prompt_and_start_import)

def select_project_folder():
    folder = filedialog.askdirectory()
    if folder:
        project_folder_path.set(folder)
        log_status(f"📁 Selected project folder: {folder}")

def ensure_remote_dir(sftp, remote_path):
    """Ensure that all directories in remote_path exist (like mkdir -p)."""
    dirs = []
    while remote_path not in ('/', ''):
        dirs.append(remote_path)
        remote_path = os.path.dirname(remote_path)
    for path in reversed(dirs):
        try:
            sftp.stat(path)
        except IOError:
            sftp.mkdir(path)
            log_status(f"📁 Created directory: {path}")

def upload_dir(sftp, local_path, remote_path):
    """Recursively uploads a folder to the remote server via SFTP."""
    ensure_remote_dir(sftp, remote_path)
    for item in os.listdir(local_path):
        local_item = os.path.join(local_path, item)
        remote_item = remote_path + "/" + item

        if os.path.isdir(local_item):
            upload_dir(sftp, local_item, remote_item)
        else:
            try:
                sftp.put(local_item, remote_item)
                log_status(f"📄 Uploaded: {remote_item}")
            except Exception as e:
                log_status(f"❌ Failed to upload {local_item} → {remote_item}: {e}")

def upload_project_folder():
    def task():
        local_dir = project_folder_path.get()
        if not local_dir:
            messagebox.showwarning("No Folder", "Please select a project folder first.")
            return

        client, username, password = get_ssh_client()
        if client is None:
            return

        project_name = Path(local_dir).name
        remote_base = f"/opt/lampp/htdocs/{project_name}"

        try:
            # Step 1: Temporarily change permission to 777
            log_status("🔓 Temporarily allowing write access to /opt/lampp/htdocs...")
            stdin, stdout, stderr = client.exec_command("sudo chmod 777 /opt/lampp/htdocs", get_pty=True)
            stdin.write(password + "\n")
            stdin.flush()
            stdout.channel.recv_exit_status()
            log_status("✅ Write permission granted.")

            # Step 2: Upload files via SFTP
            log_status(f"🚀 Uploading folder '{project_name}' to {remote_base}...")
            sftp = client.open_sftp()
            try:
                sftp.mkdir(remote_base)
            except IOError:
                pass  # Folder might already exist
            upload_dir(sftp, local_dir, remote_base)
            sftp.close()
            log_status("✅ Upload complete.")

        finally:
            # Step 3: Restore permissions
            log_status("🔒 Restoring original permissions on /opt/lampp/htdocs...")
            stdin, stdout, stderr = client.exec_command("sudo chmod 755 /opt/lampp/htdocs", get_pty=True)
            stdin.write(password + "\n")
            stdin.flush()
            stdout.channel.recv_exit_status()
            log_status("✅ Permissions restored.")

            client.close()

    threading.Thread(target=task, daemon=True).start()


def update_ci3_configs():
    def prompt_and_run():
        project_name = simpledialog.askstring("Project Name", "Enter the CI3 project folder name inside /opt/lampp/htdocs:", parent=root)
        log_status(f"📁 Selected project folder: {project_name}")
        if not project_name:
            log_status("❌ Project name not provided.")
            return
        client, username, password = get_ssh_client()
        if client is None:
            log_status("❌ SSH connection failed.")
            return

        ip = ip_entry.get().strip()
        site_url = f"http://{ip}/{project_name}/"

        # Prompt DB info on main thread
        db_name = simpledialog.askstring("DB Name", "Enter database name:", parent=root)
        if db_name is None: return
        db_user = simpledialog.askstring("DB Username", "Enter DB username:", parent=root)
        if db_user is None: return
        db_pass = simpledialog.askstring("DB Password", "Enter DB password:", show='*', parent=root)
        if db_pass is None: return

        def task():
            config_path = f"/opt/lampp/htdocs/{project_name}/application/config/config.php"
            db_path = f"/opt/lampp/htdocs/{project_name}/application/config/database.php"

            commands = [
                f"sudo sed -i \"s|\\(['\\\"]base_url['\\\"]\\][ \t]*=[ \t]*\\)['\\\"].*['\\\"];|\\1'{site_url}';|\" {config_path}",
                f"sudo sed -i \"s|\\(['\\\"]username['\\\"]\\][ \t]*=>[ \t]*\\)['\\\"].*['\\\"]\\(,\\|\\)|\\1'{db_user}'\\2|\" {db_path}",
                f"sudo sed -i \"s|'password' => '.*'|'password' => '{db_pass}'|\" {db_path}",
                f"sudo sed -i \"s|\\(['\\\"]database['\\\"]\\][ \t]*=>[ \t]*\\)['\\\"].*['\\\"]\\(,\\|\\)|\\1'{db_name}'\\2|\" {db_path}",
            ]

            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
                stdin.write(password + "\n")
                stdin.flush()
                stdout.channel.recv_exit_status()

            log_status("✅ CI3 config.php and database.php updated.")
            client.close()

        threading.Thread(target=task, daemon=True).start()

    root.after(0, prompt_and_run)  # Ensure dialogs happen on main thread

def open_ci3_project():
    project_name = simpledialog.askstring("Project Name", "Enter the CI3 project folder name inside /opt/lampp/htdocs:", parent=root)
    if not project_name:
        log_status("❌ Project name not provided.")
        return
    webbrowser.open(f"http://{ip_entry.get().strip()}/{project_name}/", new=2)

# GUI Setup
root = tk.Tk()
root.title("NtekStack Tool v1.0")
root.geometry("800x750")
root.configure(bg="#f8f9fa")
# Center the window
def center_window(window):
    window.update_idletasks()
    w = window.winfo_width()
    h = window.winfo_height()
    sw = window.winfo_screenwidth()
    sh = window.winfo_screenheight()
    x = (sw - w) // 2
    y = (sh - h) // 10
    window.geometry(f"{w}x{h}+{x}+{y}")

center_window(root)


root.resizable(False, False)

# Always keep this window on top temporarily to avoid dialogs opening behind
root.lift()
root.attributes('-topmost', True)
root.after(100, lambda: root.attributes('-topmost', False))

# Frames
header_frame = tk.Frame(root, bg="#f8f9fa")
header_frame.pack(pady=10)

input_frame = tk.LabelFrame(root, text="🔐 Server Credentials", padx=10, pady=10, bg="#f8f9fa")
input_frame.pack(padx=10, pady=5, fill="x")

actions_frame = tk.LabelFrame(root, text="🛠 Actions", padx=10, pady=10, bg="#f8f9fa")
actions_frame.pack(padx=10, pady=5, fill="x")

output_frame = tk.LabelFrame(root, text="📋 Logs", padx=10, pady=10, bg="#f8f9fa")
output_frame.pack(padx=10, pady=5, fill="both", expand=True)

# Header
tk.Label(header_frame, text="NtekStack: Remote PHP Deployment Tool", font=("Helvetica", 18, "bold"), bg="#f8f9fa").pack()

# Input Fields
tk.Label(input_frame, text="Username:", bg="#f8f9fa").grid(row=0, column=0, sticky="e")
username_entry = tk.Entry(input_frame, width=30, font=("Helvetica", 10))
username_entry.grid(row=0, column=1, padx=5, pady=5)
username_entry.focus_force()

tk.Label(input_frame, text="Password:", bg="#f8f9fa").grid(row=1, column=0, sticky="e")
password_entry = tk.Entry(input_frame, show="*", width=30, font=("Helvetica", 10))
password_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(input_frame, text="IP Address:", bg="#f8f9fa").grid(row=2, column=0, sticky="e")
ip_entry = tk.Entry(input_frame, width=30, font=("Helvetica", 10))
ip_entry.grid(row=2, column=1, padx=5, pady=5, columnspan=1)

tk.Label(input_frame, text="XAMPP Installer URL:", bg="#f8f9fa").grid(row=3, column=0, sticky="e")
xampp_url_entry = tk.Entry(input_frame, width=80, font=("Helvetica", 10))
xampp_url_entry.insert(0, DEFAULT_XAMPP_URL)
xampp_url_entry.grid(row=3, column=1, padx=5, pady=5, columnspan=2)

# Action Buttons
button_data = [
    ("1. 📥 Download XAMPP Installer", download_xampp),
    ("2. 🛠 Make Executable & Run Installer", make_executable_and_run),
    ("3. 🚀 Start LAMPP Services", start_xampp),
    ("4. 🔎 Check LAMPP's Apache/MySQL Status", check_services_status),
    ("5. 🛠 Fix phpMyAdmin Access (Allow All)", fix_phpmyadmin_access),
    ("6. 🌐 Open phpMyAdmin", open_phpmyadmin),
    ("7. 🔐 Set MySQL Root Password", set_mysql_root_password),
    ("8. 📂 Select SQL File", lambda: select_sql_file()),
    ("9. 🧩 Import SQL to MySQL", import_sql_to_mysql),
    ("10. 📁 Select CI3 Project Folder", select_project_folder),
    ("11. 🚀 Upload Project to /opt/lampp/htdocs", upload_project_folder),
    ("12. 🛠 Update CI3 config.php & database.php", update_ci3_configs),
    ("13. 🌐 Open CI3 Project", open_ci3_project),
]

sql_file_path = tk.StringVar()
project_folder_path = tk.StringVar()
for i, (text, func) in enumerate(button_data):
    btn = tk.Button(
        actions_frame, 
        text=text, 
        command=func, 
        width=40, 
        bg="#007bff", 
        fg="white", 
        relief="raised",
        anchor="w",
        cursor="hand2",
        font=("Helvetica", 10)
    )
    btn.grid(row=i // 2, column=i % 2, padx=5, pady=5, sticky="ew")



output_box = tk.Text(output_frame, height=6, wrap="word", bg="#ffffff", fg="#212529")
output_box.pack(fill="both", expand=True)

# Footer Frame (always visible)
footer_frame = tk.Frame(root, bg="#f8f9fa")
footer_frame.pack(side="bottom", fill="x", pady=(0, 10))

footer_text = (
    "🛠 Developed by Mikhan Balbastro — Ntek Systems' Web Developer\n"
    "🧪 Version 1.0 • Currently in Beta • Please report bugs or suggestions\n"
    "📧 Contact: mikhan.balbastro@nteksystems.com"
)

tk.Label(
    footer_frame,
    text=footer_text,
    font=("Helvetica", 9),
    bg="#f8f9fa",
    fg="#6c757d",
    justify="center"
).pack()

def log_status(message):
    output_box.insert(tk.END, message + "\n")
    output_box.see(tk.END)
    root.update_idletasks()



root.mainloop()
