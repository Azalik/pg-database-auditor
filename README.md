# PostgreSQL Health & Security Auditor

A lightweight Python utility designed for database administrators and security engineers to audit PostgreSQL instances for security misconfigurations and performance bottlenecks.

## 🚀 Features

- **Security Audit:**
  - Scans for users with dangerous `SUPERUSER` privileges.
  - Detects public schema objects accessible by `PUBLIC` (potential data leakage risks).
- **Performance Audit:**
  - Identifies unused or rarely used indexes (`<100` scans) to optimize database storage and write performance.
- **Automation & Reporting:**
  - Clean tabular CLI output powered by `PrettyTable`.
  - Secure database connectivity via SQLAlchemy and `psycopg` (v3).

## ⚙️ Installation & Usage

1. Clone the repository:
bash
git clone https://github.com/Azalik/pg-database-auditor.git
cd pg_auditor

2. Create and activate a virtual environment:
bash
python3 -m venv venv
source venv/bin/activate

3. Install dependencies:
bash
pip install -r requirements.txt

4. Run the auditor script:
bash
python auditor.py --db your_database --user your_username --password 'your_password'


## 🛠️ Tech Stack
- Python 3
- SQLAlchemy (ORM & Core)
- Psycopg 3 (PostgreSQL Driver)
- PrettyTable
