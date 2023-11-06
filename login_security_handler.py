"""
Functions to aid in handling malicious login attempts
"""

from collections import defaultdict
from datetime import datetime, timedelta

login_attempts = defaultdict(int)
last_failed_attempt = defaultdict(lambda: datetime.min)
ban_list = set()

BAN_THRESHOLD = 3
BAN_TIME = timedelta(minutes=30)


def check_ip(ip):
    """
    Checks if attempting ip is already banned
    :param ip:
    :return:
    """
    current_time = datetime.now()
    if ip in ban_list and (current_time - last_failed_attempt[ip] > BAN_TIME):
        ban_list.remove(ip)
        reset_ip_attempts(ip)
    if ip in ban_list:
        raise ValueError("This IP has been banned due to excessive login attempts.")


def log_failed_attempt(ip):
    """
    Upticks IP failed logins.
    If greater than attempts, adds to ban list.
    :param ip:
    :return:
    """
    login_attempts[ip] += 1
    last_failed_attempt[ip] = datetime.now()
    if login_attempts[ip] > BAN_THRESHOLD:
        ban_list.add(ip)


def reset_ip_attempts(ip):
    """
    Resets the ip login attempts, for when they successfully login
    :param ip:
    :return:
    """
    login_attempts[ip] = 0
