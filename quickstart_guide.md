# 🚀 Quick Start Guide - Secure File Transfer System

Get your secure file transfer system running in 5 minutes!

## 📦 Step-by-Step Setup

### 1. Create Project Structure

```bash
mkdir secure_file_transfer
cd secure_file_transfer
mkdir templates uploads
```

### 2. Create Files

Save the following files in your project:

```
secure_file_transfer/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── setup_database.sql     # Database setup script
├── templates/
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   └── dashboard.html    # Main dashboard
└── uploads/              # File storage directory
```

### 3. Install Python Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 4. Setup MySQL Database

**Option A: Using MySQL Command Line**

```bash
mysql -u root -p < setup_database.sql
```

**Option B: Using MySQL Workbench**

1. Open MySQL Workbench
2. Connect to your MySQL server
3. Open `setup_database.sql`
4. Execute the script

**Option C: Manual Setup**

```bash
mysql -u root -p
```

Then paste:

```sql
CREATE DATABASE secure_file_transfer;
USE secure_file_transfer;
-- Copy the table creation statements from setup_database.sql
```

### 5. Configure Application

Edit `app.py` and update:

```python
# Database credentials
DB_CONFIG = {
    'host': 'localhost',
    'user': 'fileapp_user',        # or 'root'
    'password': 'your_password',   # Change this!
    'database': 'secure_file_transfer'
}

# Secret key
app.secret_key = 'your-secret-key-change-in-production'  # Change this!
```

**Generate a secure secret key:**

```python
python -c "import secrets; print(secrets.token_hex(32))"
```

### 6. Run the Application

```bash
python app.py
```

You should see:

```
Database initialized successfully
 * Running on http://0.0.0.0:5000
```

### 7. Access the Application

Open your browser and go to:

**http://localhost:5000**

## 🎯 First Steps

### Create Your First User

1. Click **"Register here"**
2. Enter username: `admin`
3. Enter password: `SecurePass123!`
4. Click **"Register"**
5. Wait for success message
6. You'll be redirected to login

### Login

1. Enter your credentials
2. Click **"Login"**
3. You'll be taken to the dashboard

### Send Your First File

1. Create a second user account (to send files to)
2. Login with your first account
3. Click **"Send File"** in sidebar
4. Select recipient
5. Choose a file
6. Click **"Encrypt & Send"**
7. File will be encrypted and sent!

### Receive Files

1. Login with the recipient account
2. Click **"Receive Files"** in sidebar
3. Click **"Decrypt & Download"**
4. File will be decrypted and downloaded

## ✅ Verification Checklist

- [ ] MySQL server is running
- [ ] Database `secure_file_transfer` exists
- [ ] All tables created (users, files, logs)
- [ ] Python dependencies installed
- [ ] `uploads/` directory exists and is writable
- [ ] Database credentials configured in `app.py`
- [ ] Secret key changed in `app.py`
- [ ] Application starts without errors
- [ ] Can access http://localhost:5000
- [ ] Can register a new user
- [ ] Can login successfully
- [ ] Can send a file
- [ ] Can receive and decrypt a file

## 🔧 Common Issues & Solutions

### Issue: "Module not found" error

**Solution:**
```bash
pip install -r requirements.txt --force-reinstall
```

### Issue: "Access denied for user" (MySQL)

**Solution:**
```sql
-- In MySQL, run:
GRANT ALL PRIVILEGES ON secure_file_transfer.* TO 'your_user'@'localhost';
FLUSH PRIVILEGES;
```

Or use `root` user temporarily:
```python
DB_CONFIG = {
    'user': 'root',
    'password': 'your_root_password',
    # ...
}
```

### Issue: Port 5000 already in use

**Solution:**

Change port in `app.py`:
```python
app.run(debug=True, port=5001)  # Use 5001 instead
```

### Issue: "Can't connect to MySQL server"

**Solutions:**

1. Check if MySQL is running:
   ```bash
   # Linux/Mac
   sudo systemctl status mysql
   
   # Windows
   net start MySQL80
   ```

2. Verify connection:
   ```bash
   mysql -u root -p
   ```

3. Check host/port in `DB_CONFIG`

### Issue: Template not found

**Solution:**

Ensure folder structure is correct:
```
secure_file_transfer/
├── app.py
└── templates/          # Must be named 'templates'
    ├── login.html
    ├── register.html
    └── dashboard.html
```

### Issue: File upload fails

**Solutions:**

1. Check `uploads/` directory exists
2. Verify write permissions:
   ```bash
   chmod 755 uploads/
   ```
3. Check file size limit in `app.py`

## 🎨 Customization Tips

### Change Theme Color

Replace `#004aff` with your color in all HTML files:

```css
background: #004aff;  /* Your color here */
```

### Change Session Timeout

In `app.py`:
```python
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
```

### Change Max File Size

In `app.py`:
```python
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
```

## 📊 Testing the System

### Test Encryption Flow

1. Register two users: `alice` and `bob`
2. Login as `alice`
3. Send a text file to `bob`
4. Logout and login as `bob`
5. Download the file
6. Verify content is correct

### Test Security Features

1. Try logging in with wrong password 3 times
2. Account should be locked for 15 minutes
3. Check logs table to see recorded attempts

### Test File Types

Try sending:
- Text files (.txt)
- Images (.jpg, .png)
- Documents (.pdf, .docx)
- Archives (.zip)

All should work!

## 🚀 Next Steps

- [ ] Add more users
- [ ] Test with larger files
- [ ] Check logs regularly
- [ ] Backup database
- [ ] Consider deployment (see README.md)
- [ ] Enable HTTPS for production
- [ ] Set up regular database backups

## 📚 Resources

- **Full Documentation**: See README.md
- **Flask Docs**: https://flask.palletsprojects.com/
- **MySQL Docs**: https://dev.mysql.com/doc/
- **PyCryptodome Docs**: https://pycryptodome.readthedocs.io/

## 🆘 Need Help?

1. Check error messages in terminal
2. Review browser console (F12)
3. Check MySQL logs
4. Verify all configuration settings
5. Ensure all dependencies are installed

---

**Congratulations! 🎉**

Your secure file transfer system is ready to use!

Remember to:
- Use strong passwords
- Never share private keys
- Keep the system updated
- Monitor logs regularly
- Backup your database

Happy secure file sharing! 🔐