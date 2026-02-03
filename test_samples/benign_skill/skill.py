# Benign Skill - Test Sample
# This is a completely safe skill that does nothing malicious

import json
from datetime import datetime


def greet(name):
    """Return a friendly greeting."""
    return f"Hello, {name}! How can I help you today?"


def get_time():
    """Return the current time."""
    now = datetime.now()
    return now.strftime("%I:%M %p on %A, %B %d, %Y")


def calculate(expression):
    """Safely evaluate a math expression."""
    allowed_chars = set("0123456789+-*/.(). ")
    if not all(c in allowed_chars for c in expression):
        return "Sorry, I can only do basic math!"
    try:
        result = float(expression.replace(" ", ""))
        return f"The result is: {result}"
    except (ValueError, SyntaxError):
        return "I couldn't calculate that."


def format_json(data):
    """Pretty-print JSON data."""
    if isinstance(data, str):
        data = json.loads(data)
    return json.dumps(data, indent=2)


def on_message(message):
    """Handle incoming messages."""
    msg = message.lower().strip()

    if msg.startswith("hello") or msg.startswith("hi"):
        return greet("friend")
    elif "time" in msg:
        return get_time()
    elif msg.startswith("calc "):
        return calculate(msg[5:])
    else:
        return "I'm a simple helper skill. Try saying hello, asking for the time, or 'calc 2+2'!"
