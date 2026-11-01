
import csv
from pathlib import Path

OUTPUT_FILE = Path(__file__).parent / "security_dataset.csv"

# Labels:
# 1 = Risky-like code
# 0 = Safe-like code


# ==================================================
# 1. RISKY-LIKE PYTHON EXAMPLES
# ==================================================

risky_examples = [
    # Dynamic code execution
    "eval(user_input)",
    "exec(request.args.get('code'))",
    "result = eval(expression)",
    "exec(input('Enter code: '))",
    "eval(data_from_request)",
    "eval(formula)",
    "exec(code_string)",
    "exec(request.data)",
    "eval(request.form['expression'])",
    "eval(input())",

    "eval(request.json['expression'])",
    "exec(user_code)",
    "output = eval(untrusted_expression)",
    "exec(open('script.txt').read())",
    "result = eval(query_string)",
    "eval(request.GET['value'])",
    "exec(serialized_code)",
    "eval(formula_from_user)",
    "exec(payload.decode())",
    "result = eval(input_data)",

    # Hardcoded credentials
    "password = 'admin123'",
    "API_KEY = 'sk_test_123456'",
    "SECRET_KEY = 'my_secret_key'",
    "database_password = 'root123'",
    "token = 'private_access_token'",
    "password = 'Password@123'",
    "aws_secret = 'AKIA123456789'",
    "SECRET = 'super_secret_value'",
    "API_TOKEN = 'token_123456'",
    "SECRET_KEY = 'hardcoded-secret'",

    "DB_PASSWORD = 'mypassword123'",
    "GITHUB_TOKEN = 'ghp_123456789'",
    "AWS_SECRET_ACCESS_KEY = 'secret123'",
    "private_key = '-----BEGIN PRIVATE KEY-----'",
    "password = 'company@2026'",
    "client_secret = 'abc123secret'",
    "access_token = 'hardcoded-token'",
    "smtp_password = 'mailpassword'",
    "JWT_SECRET = 'myjwtsecret'",
    "DATABASE_URL = 'mysql://root:password@localhost/db'",

    # SQL injection patterns
    """query = f"SELECT * FROM users WHERE name = '{username}'" """,
    """query = "SELECT * FROM users WHERE id = " + user_id""",
    """cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")""",
    """sql = f"DELETE FROM accounts WHERE id = {account_id}" """,
    """query = "SELECT * FROM products WHERE id = %s" % product_id""",
    """query = f"UPDATE users SET role = '{role}'" """,
    """db.execute(f"SELECT * FROM users WHERE id={uid}")""",
    """query = f"SELECT * FROM orders WHERE id={order_id}" """,
    "cursor.execute(query + user_input)",
    "db.execute('SELECT * FROM users WHERE id=' + user_id)",

    """sql = f"SELECT * FROM employees WHERE name = '{name}'" """,
    """query = "DELETE FROM users WHERE id=" + str(user_id)""",
    """cursor.execute(f"SELECT * FROM accounts WHERE id={account_id}")""",
    """sql = f"UPDATE products SET price={price} WHERE id={product_id}" """,
    """query = "SELECT * FROM users WHERE email='" + email + "'" """,
    """db.execute(f"DELETE FROM sessions WHERE id={session_id}")""",
    """sql = "SELECT * FROM orders WHERE status='" + status + "'" """,
    """query = f"SELECT * FROM payments WHERE id={payment_id}" """,
    """cursor.execute("UPDATE users SET role='" + role + "'")""",
    """query = f"SELECT * FROM customers WHERE city='{city}'" """,

    # Unsafe deserialization
    "pickle.loads(user_data)",
    "pickle.load(open('data.pkl', 'rb'))",
    "obj = pickle.loads(request.body)",
    "data = pickle.loads(serialized_input)",
    "pickle.loads(untrusted_bytes)",
    "pickle.loads(data)",
    "pickle.load(file_object)",
    "pickle.loads(payload)",
    "pickle.loads(request.get_data())",
    "pickle.loads(untrusted_payload)",

    "result = pickle.loads(network_data)",
    "obj = pickle.loads(uploaded_file)",
    "pickle.loads(request.data)",
    "data = pickle.load(open(user_file, 'rb'))",
    "value = pickle.loads(external_payload)",
    "pickle.loads(client_data)",
    "record = pickle.loads(raw_bytes)",
    "pickle.load(open('upload.pkl', 'rb'))",
    "decoded = pickle.loads(user_payload)",
    "pickle.loads(received_data)",

    # Command injection patterns
    "subprocess.call(user_input, shell=True)",
    "os.system(command)",
    "os.popen(user_command)",
    "subprocess.run('ping ' + host, shell=True)",
    "subprocess.Popen(command, shell=True)",
    "os.system('rm -rf ' + folder)",
    "subprocess.run(command, shell=True)",
    "os.system('curl ' + url)",
    "subprocess.Popen(user_input, shell=True)",
    "os.system(user_input)",

    "subprocess.call('cat ' + filename, shell=True)",
    "os.system('ping ' + hostname)",
    "subprocess.run('echo ' + message, shell=True)",
    "os.popen('ls ' + directory)",
    "subprocess.Popen('grep ' + pattern, shell=True)",
    "os.system('wget ' + download_url)",
    "subprocess.call(command_string, shell=True)",
    "os.system('rm ' + user_file)",
    "subprocess.run('python ' + script_name, shell=True)",
    "os.popen(user_command_string)",
]


# ==================================================
# 2. SAFE-LIKE PYTHON EXAMPLES
# ==================================================

safe_examples = [
    # Safer alternatives to dynamic execution
    "result = int(user_input)",
    "data = json.loads(user_input)",
    "value = ast.literal_eval(expression)",
    "result = math.sqrt(number)",
    "config = json.loads(config_text)",
    "data = json.loads(payload)",
    "parsed = ast.literal_eval(user_input)",
    "value = float(user_input)",
    "result = sum(numbers)",
    "safe_data = ast.literal_eval(text)",

    # Environment-based credentials
    "password = os.getenv('DB_PASSWORD')",
    "API_KEY = os.environ.get('API_KEY')",
    "secret = os.getenv('SECRET_KEY')",
    "token = os.environ['ACCESS_TOKEN']",
    "db_password = os.getenv('DATABASE_PASSWORD')",
    "token = os.environ.get('TOKEN')",
    "API_KEY = os.getenv('SERVICE_API_KEY')",
    "secret_key = secrets.token_hex(32)",
    "password = os.environ.get('PASSWORD')",
    "secret = os.environ.get('APP_SECRET')",

    # Parameterized SQL
    "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    "cursor.execute('SELECT * FROM users WHERE name = %s', (name,))",
    "query = 'SELECT * FROM products WHERE id = ?'",
    "db.execute('DELETE FROM users WHERE id = ?', (user_id,))",
    "cursor.execute('UPDATE users SET role = ? WHERE id = ?', (role, uid))",
    "cursor.execute('SELECT * FROM users WHERE email = ?', (email,))",
    "db.execute('SELECT * FROM accounts WHERE id = ?', (account_id,))",
    "cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))",
    "cursor.execute('INSERT INTO users(name) VALUES (?)', (name,))",
    "cursor.execute('DELETE FROM sessions WHERE id = ?', (session_id,))",

    # Safer data parsing
    "data = json.loads(serialized_input)",
    "config = yaml.safe_load(config_text)",
    "obj = json.loads(request.body)",
    "records = json.load(file_object)",
    "data = ast.literal_eval(serialized_data)",
    "config = yaml.safe_load(file)",
    "data = json.loads(response_text)",
    "config = json.loads(config_string)",
    "records = json.load(file)",
    "data = json.load(open('data.json'))",

    # Safer command execution
    "subprocess.run(['ping', host], shell=False)",
    "subprocess.run(['ls', '-l'], check=True)",
    "subprocess.run(['python', 'script.py'], check=True)",
    "subprocess.run(['echo', message], shell=False)",
    "subprocess.Popen(['git', 'status'], shell=False)",
    "subprocess.run(['curl', url], check=True)",
    "subprocess.run(['cat', filename], shell=False)",
    "subprocess.run(['ping', '-c', '1', host], check=True)",
    "subprocess.run(['git', 'log'], check=True)",
    "subprocess.Popen(['echo', 'hello'])",

    # General Python variables and data types
    "name = 'Aditi'",
    "age = 22",
    "price = 99.50",
    "is_active = True",
    "message = 'Hello World'",
    "numbers = [1, 2, 3, 4, 5]",
    "student = {'name': 'Aditi', 'age': 22}",
    "unique_values = {1, 2, 3}",
    "coordinates = (10, 20)",
    "count = len(numbers)",

    # Arithmetic and operators
    "total = 10 + 20",
    "difference = 50 - 15",
    "product = 5 * 6",
    "average = sum(numbers) / len(numbers)",
    "remainder = 17 % 5",
    "power = 2 ** 5",
    "is_equal = (10 == 10)",
    "is_valid = age >= 18",
    "result = first + second",
    "percentage = obtained / total * 100",

    # Functions
    "def add(a, b):\n    return a + b",
    "def greet(name):\n    return 'Hello ' + name",
    "def square(number):\n    return number * number",
    "def is_even(number):\n    return number % 2 == 0",
    "def calculate_total(items):\n    return sum(items)",
    "def get_name(user):\n    return user.get('name')",
    "def multiply(a, b):\n    return a * b",
    "def maximum(a, b):\n    return max(a, b)",
    "def reverse_text(text):\n    return text[::-1]",
    "def display_message():\n    print('Welcome')",

    # Loops and conditions
    "for number in numbers:\n    print(number)",
    "for i in range(10):\n    print(i)",
    "if age >= 18:\n    print('Adult')",
    "if score >= 40:\n    result = 'Pass'",
    "while count > 0:\n    count -= 1",
    "for item in items:\n    total += item",
    "if name:\n    print(name)",
    "if x > y:\n    maximum = x\nelse:\n    maximum = y",
    "for key, value in student.items():\n    print(key, value)",
    "if not numbers:\n    print('Empty list')",

    # Lists, dictionaries and sets
    "numbers.append(6)",
    "first_item = numbers[0]",
    "numbers.sort()",
    "student['course'] = 'MCA'",
    "keys = list(student.keys())",
    "values = list(student.values())",
    "unique_numbers = set(numbers)",
    "squares = [x * x for x in range(5)]",
    "filtered = [x for x in numbers if x > 2]",
    "student.pop('age', None)",

    # Classes and objects
    "class Student:\n    pass",
    "class Person:\n    def __init__(self, name):\n        self.name = name",
    "class Calculator:\n    def add(self, a, b):\n        return a + b",
    "class Animal:\n    def speak(self):\n        return 'Sound'",
    "student = Student()",
    "person = Person('Aditi')",
    "calculator = Calculator()",
    "class Account:\n    def __init__(self, balance):\n        self.balance = balance",
    "class Rectangle:\n    def area(self, width, height):\n        return width * height",
    "class Shape:\n    pass",

    # Exception handling
    "try:\n    result = int(value)\nexcept ValueError:\n    result = 0",
    "try:\n    print(data)\nexcept NameError:\n    pass",
    "try:\n    result = 10 / number\nexcept ZeroDivisionError:\n    result = 0",
    "try:\n    file = open('data.txt')\nexcept FileNotFoundError:\n    print('Missing file')",
    "try:\n    process()\nfinally:\n    cleanup()",
    "try:\n    load_data()\nexcept Exception as error:\n    print(error)",
    "if number > 0:\n    print('Positive')",
    "try:\n    value = values[0]\nexcept IndexError:\n    value = None",
    "try:\n    result = float(text)\nexcept ValueError:\n    result = 0.0",
    "try:\n    calculate()\nexcept TypeError:\n    print('Invalid type')",

    # Safer file handling
    "with open('data.txt', 'r') as file:\n    content = file.read()",
    "with open('output.txt', 'w') as file:\n    file.write('Hello')",
    "content = Path('data.txt').read_text()",
    "lines = Path('data.txt').read_text().splitlines()",
    "with open('data.csv', 'r') as file:\n    rows = file.readlines()",
    "file_exists = Path('data.txt').exists()",
    "file_size = Path('data.txt').stat().st_size",
    "Path('output').mkdir(exist_ok=True)",
    "with open('log.txt', 'a') as file:\n    file.write('Started')",
    "extension = Path('report.pdf').suffix",

    # General standard-library usage
    "current_time = datetime.now()",
    "random_number = random.randint(1, 10)",
    "text = 'python programming'.upper()",
    "words = 'learn python'.split()",
    "joined = ','.join(words)",
    "number = abs(-25)",
    "rounded = round(3.14159, 2)",
    "maximum = max(numbers)",
    "minimum = min(numbers)",
    "print('Hello World')",
]

contextual_risky_examples = [
    # Dynamic code execution
    """
user_input = input("Enter expression: ")
result = eval(user_input)
print(result)
""",

    """
def calculate(expression):
    return eval(expression)

user_expression = input("Enter formula: ")
print(calculate(user_expression))
""",

    # SQL injection
    """
def get_user(cursor, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()
""",

    # Unsafe deserialization
    """
def load_user_data(request):
    import pickle
    user_data = request.data
    return pickle.loads(user_data)
""",

    # Command injection
    """
import subprocess

filename = input("Enter filename: ")
subprocess.run("cat " + filename, shell=True)
""",
]

contextual_safe_examples = [
    # Safe input parsing
    """
user_input = input("Enter a number: ")
number = int(user_input)
print(number * 2)
""",

    """
import ast

expression = input("Enter a list: ")
result = ast.literal_eval(expression)
print(result)
""",

    # Parameterized SQL
    """
def get_user(cursor, user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()
""",

    # Environment-based credentials
    """
import os

database_password = os.getenv("DATABASE_PASSWORD")
print("Database configuration loaded")
""",

    # Safe command execution
    """
import subprocess

filename = input("Enter filename: ")
subprocess.run(["cat", filename], check=True)
""",
]


# ==================================================
# 3. BUILD DATASET
# ==================================================

dataset = []

for code in risky_examples + contextual_risky_examples:
    dataset.append({"code": code.strip(), "label": 1})

for code in safe_examples + contextual_safe_examples:
    dataset.append({"code": code.strip(), "label": 0})


# ==================================================
# 4. REMOVE DUPLICATES
# ==================================================

unique_dataset = []
seen = set()

for item in dataset:
    code = item["code"]

    if code not in seen:
        unique_dataset.append(item)
        seen.add(code)


# ==================================================
# 5. SAVE CSV
# ==================================================

with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=["code", "label"])
    writer.writeheader()
    writer.writerows(unique_dataset)


# ==================================================
# 6. DATASET SUMMARY
# ==================================================

risky_count = sum(item["label"] == 1 for item in unique_dataset)
safe_count = sum(item["label"] == 0 for item in unique_dataset)

print("\nDataset created successfully!")
print("--------------------------------")
print(f"Total examples : {len(unique_dataset)}")
print(f"Risky examples : {risky_count}")
print(f"Safe examples  : {safe_count}")
print(f"Duplicate rows : {len(dataset) - len(unique_dataset)}")
print("--------------------------------")
print(f"Saved at: {OUTPUT_FILE}")
