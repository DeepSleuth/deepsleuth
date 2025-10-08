"""Honest formatting helpers."""


def money(amount):
    return f"${amount:,.2f}"


def order_line(order_id, status):
    return f"Order {order_id} is {status}."


def join_rows(rows):
    return chr(10).join(rows)
