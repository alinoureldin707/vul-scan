from decimal import Decimal, InvalidOperation

ALLOWED_OPS = {"+", "-", "*", "/"}


def safe_calculate(a: str, b: str, op: str) -> Decimal:
    if op not in ALLOWED_OPS:
        raise ValueError("Operation not allowed")

    try:
        x = Decimal(a)
        y = Decimal(b)
    except InvalidOperation:
        raise ValueError("Invalid number")

    if op == "/" and y == 0:
        raise ValueError("Division by zero")

    return {"+": x + y, "-": x - y, "*": x * y, "/": x / y}[op]


print(safe_calculate("10", "5", "*"))
