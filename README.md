# Solana Vault

A demonstration application showcasing common web2 security vulnerabilities in a web3 context. This project is designed for educational purposes to help developers understand and identify security vulnerabilities in web applications.

## ⚠️ Important Disclaimer

This application contains **intentional security vulnerabilities** and should **never** be used in production. It is designed solely for educational purposes to demonstrate common security issues in web applications.

**DO NOT** use real credentials or connect real wallets to this application.

## 🎯 Project Overview

Solana Vulnerable Bank is a web application that simulates a banking system with Solana wallet integration. The application intentionally includes various security vulnerabilities commonly found in web applications, including:

- Cross-Site Scripting (XSS)
- Server Side Request Forgery (SSRF)
- File Upload Vulnerability
- Broken Authentication
- Broken Access Control
- Security Misconfiguration
- Insecure Deserialization
- Using Components with Known Vulnerabilities
- Insufficient Logging & Monitoring

## 🛠️ Technical Stack

- **Backend**: Python Flask
- **Database**: SQLite
- **Frontend**: HTML, CSS, JavaScript
- **Authentication**: Session-based
- **Wallet Integration**: Solana

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Basic understanding of web security concepts

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/5wnstar/solana_web2_vuln
cd solana_web2_vuln
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
flask init-db
```

5. Run the application:
```bash
flask run
```

The application will be available at `http://localhost:5000`

## 🔍 Security Vulnerabilities

This application intentionally includes the following vulnerabilities:

### 1. Cross-Site Scripting (XSS)
- Stored XSS in comments section
- Reflected XSS in search functionality
- DOM-based XSS in profile section


### 2. Broken Authentication
- Weak password requirements
- Session fixation
- Insecure token storage
- Missing rate limiting

### 3. Broken Access Control
- Missing authorization checks
- Insecure direct object references
- Missing function-level access control

### 4. Security Misconfiguration
- Debug mode enabled
- Default credentials
- Verbose error messages
- Missing security headers

### 5. Insecure Deserialization
- Unsafe JSON parsing
- Insecure file upload handling

### 6. Using Components with Known Vulnerabilities
- Outdated dependencies
- Known vulnerable packages

### 7. Insufficient Logging & Monitoring
- Missing audit logs
- No security event logging
- No monitoring for suspicious activities

## 🎓 Learning Objectives

By studying this application, you can learn:

1. How to identify common web security vulnerabilities
2. The impact of web2 security vulnerabilities on web3 applications
3. Best practices for secure web development
4. How to test for security vulnerabilities
5. How to implement proper security measures

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/2.0.x/security/)
- [Solana Security Guidelines](https://docs.solana.com/security)
- [Web Security Fundamentals](https://portswigger.net/web-security)


## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

This application is intentionally vulnerable and should only be used in a controlled environment for educational purposes. The maintainers are not responsible for any misuse or damage caused by this application.

## 🙏 Acknowledgments

- OWASP for their security guidelines
- Flask community for the web framework
