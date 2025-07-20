# 🛠 NtekStack Tool v1.0

A Python-based GUI tool that allows the users to remotely install and manage **XAMPP**, and the company's Code Igniter Project on a Linux server via SSH.

## 🔧 Features

- ✅ SSH connection to remote Linux server
- 📥 Download & install XAMPP (silent/unattended mode)
- ▶️ Start/stop XAMPP services
- 🔐 Set MySQL root password
- 📂 Upload CI3 project folder to `/opt/lampp/htdocs/`
- 🧩 Import SQL file to remote MySQL database
- 🌐 Fix phpMyAdmin access and open it in your browser
- ⚙️ Auto-update `config.php` and `database.php` for CI3

---

## 🖥 GUI Preview



---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
    git clone https://github.com/Mikhan-TMP/NtekStack-Tool.git
    cd ntekstack-tool
```
### 2. Create a Virtual Environment.
```bash
    python -m venv venv
    venv\Scripts\activate  # On Windows
    # OR
    source venv/bin/activate  # On Linux/Mac
```
### 3. Install Dcependencies
```bash
    pip install -r requirements.txt
```
### 4. Run the Application.
```bash
    python installer.py
```

#### NOTE: Building this as an executable is not yet prod-ready therefore, it is still on-going. 
