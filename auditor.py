import argparse
import sys
from prettytable import PrettyTable
from sqlalchemy import create_engine, text

# Настройка аргументов командной строки
parser = argparse.ArgumentParser(description="PostgreSQL Database Health & Security Auditor")
parser.add_argument("--host", default="localhost", help="Database host")
parser.add_argument("--port", default="5432", help="Database port")
parser.add_argument("--db", required=True, help="Database name")
parser.add_argument("--user", required=True, help="Database user")
parser.add_argument("--password", required=True, help="Database password")
args = parser.parse_args()

# Формирование строки подключения (DSN) с использованием драйвера psycopg (v3)
db_uri = f"postgresql+psycopg://{args.user}:{args.password}@{args.host}:{args.port}/{args.db}"


def run_query(query_text):
  """Выполняет SQL-запрос и возвращает результат."""
  try:
    engine = create_engine(db_uri)
    with engine.connect() as connection:
      result = connection.execute(text(query_text))
      return result.fetchall()
  except Exception as e:
    print(f"Error connecting to database: {e}")
    sys.exit(1)


def check_security_risks():
  print("\n--- SECURITY AUDIT ---")

  # Проверка 1: Пользователи с правами SUPERUSER (критический риск)
  su_query = "SELECT rolname FROM pg_roles WHERE rolsuper = true AND rolname != 'postgres';"
  su_results = run_query(su_query)
  print(f"Found {len(su_results)} users with SUPERUSER privileges:")
  table = PrettyTable(["Superuser Role"])
  for row in su_results:
    table.add_row([row[0]])
  print(table)

  # Проверка 2: Объекты в схеме public, доступные всем (возможная утечка данных)
  public_query = """
        SELECT tp.table_schema, tp.table_name, t.table_type, tp.grantee
        FROM information_schema.table_privileges tp
        JOIN information_schema.tables t
          ON tp.table_schema = t.table_schema AND tp.table_name = t.table_name
        WHERE tp.table_schema = 'public' AND tp.grantee = 'PUBLIC';
    """
  pub_results = run_query(public_query)
  print(
      f"\nFound {len(pub_results)} objects in public schema accessible by"
      " PUBLIC:"
  )
  table = PrettyTable(["Schema", "Name", "Type", "Grantee"])
  for row in pub_results:
    table.add_row([row[0], row[1], row[2], row[3]])
  print(table)


def check_performance_bottlenecks():
  print("\n--- PERFORMANCE AUDIT ---")

  # Проверка 1: Индексы, которые читаются редко (кандидаты на удаление)
  unused_idx_query = """
        SELECT relname AS table_name, indexrelname AS index_name, idx_scan, idx_tup_read, idx_tup_fetch
        FROM pg_stat_user_indexes
        WHERE idx_scan < 100 ORDER BY idx_scan ASC LIMIT 10;
    """
  idx_results = run_query(unused_idx_query)
  print("Top 10 indexes with low usage (<100 scans):")
  table = PrettyTable(["Table", "Index", "Scans", "Tup Read", "Tup Fetch"])
  for row in idx_results:
    table.add_row([row[0], row[1], row[2], row[3], row[4]])
  print(table)


if __name__ == "__main__":
  print(f"Starting audit for database: {args.db} on {args.host}")
  check_security_risks()
  check_performance_bottlenecks()
  print("\n--- Audit Finished ---")
