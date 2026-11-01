
from backend.ml.predict import predict_code

test_cases = {
    "Risky - eval": "eval(user_input)",
    "Risky - pickle": "pickle.loads(user_data)",
    "Risky - SQL": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
    "Safe - print": "print(123)",
    "Safe - arithmetic": "total = 10 + 20",
    "Safe - function": "def add(a, b):\n    return a + b",
    "Safe - environment variable": "token = os.environ['ACCESS_TOKEN']",
}

print("\n========== ML PREDICTION TESTS ==========")

for name, code in test_cases.items():
    result = predict_code(code)

    print(f"\n{name}")
    print(f"Code: {code}")
    print(f"Prediction: {result['prediction']}")
    print(f"Risk score: {result['risk_score']}")
