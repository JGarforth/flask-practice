"""
A series of functions to generate databases and authenticate users.
"""

import hashlib
import logging
import re
import sqlite3 as sql
import secrets
from datetime import datetime
from flask import request


logger = logging.getLogger('failed_logins')
logger.setLevel(logging.INFO)
log_file = logging.FileHandler('failed_logins.log')
log_file.setLevel(logging.INFO)
logger.addHandler(log_file)


def generate_table():
    """
    Generates an SQLite table of userData if it doesn't already exist.
    Each table has 3 columns, to store username, password hash, and salt.
    :return:
    """
    conn = sql.connect('userInfo.db')

    def table_exists(connect):
        """
        Checks if table already exists.
        :param connect:
        :return: Returns True orFalse based on if the table already exists or not.
        """
        temp_cursor = connect.cursor()
        temp_cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='userInfo'
        """)
        return temp_cursor.fetchone() is not None

    if table_exists(conn):
        return

    cursor = conn.cursor()
    cursor.execute(
        'CREATE TABLE userInfo (Username, Password, Salt)'
    )

    conn.commit()
    conn.close()


def new_user(username, password):
    """
    Adds new user data to the sql table. Generates a salt and calls
    salt_and_hash to get the password to be stored.
    :param username: If the username already exists, an error is raised.
    :param password:
    :return:
    """
    conn = sql.connect('userInfo.db')
    cursor = conn.cursor()

    query = 'SELECT Username FROM userInfo WHERE Username=?'
    result = cursor.execute(query, (username,)).fetchone()
    if result:
        conn.close()
        raise ValueError('Username is already in use')

    salt = secrets.token_hex()
    password = salt_and_hash(salt, password)

    data = (username, password, salt)
    query = 'INSERT INTO userInfo (Username, Password, Salt) ' \
            'VALUES (?,?,?)'

    cursor.execute(query, data)
    conn.commit()
    conn.close()


def salt_and_hash(salt, password):
    """
    Generates a generated salt and securely hashes everything together.
    :param salt:
    Salt is hashed along with hashed password.
    :param password:
    Password is hashed twice.
    :return:
    Returns the final hash.
    """
    password = password.encode()
    hashed_password = hashlib.sha256(password).hexdigest()
    hashed_password = hashed_password.encode()
    salt = salt.encode()
    final_hash = hashlib.sha256(hashed_password + salt).hexdigest()
    return final_hash


def verify_user(username_input, password_input):
    """
    Verifies whether a user can log in or not.
    :param username_input:
    Used to query the database. ValueError if username doesn't return anything.
    :param password_input:
    Hashed to see if it matches the original password.
    :return:
    Error is raised in the event of authentication failure. Otherwise, user is authorized.
    """
    conn = sql.connect('userInfo.db')
    cursor = conn.cursor()

    cursor.execute('SELECT Salt, Password FROM userInfo WHERE Username=?', (username_input,))
    row = cursor.fetchone()
    if row is None:
        time_of_failure = datetime.now().strftime('%m-%d-%Y %H:%M:%S')
        logger.info("INVALID LOGIN AT: %s FROM: %s WITH USERNAME: %s",
                    time_of_failure, request.remote_addr, username_input)
        conn.close()
        raise ValueError("Invalid username and/or password")

    salt, original_password = row
    password_attempt = salt_and_hash(salt, password_input)

    if password_attempt != original_password:
        time_of_failure = datetime.now().strftime('%m-%d-%Y %H:%M:%S')
        logger.info("INVALID LOGIN AT: %s FROM: %s WITH USERNAME: %s",
                    time_of_failure, request.remote_addr, username_input)
        conn.close()
        raise ValueError("* Invalid username and/or password")

    conn.close()


def verify_password(password_input):
    """
    First verifies that the password is not one of the common passwords in the txt.
    Then verifies that the input password is at least 12 characters in length, has at least
    1 lowercase, 1 uppercase, 1 symbol, and 1 number using a regular expression.
    If it doesn't pass, a ValueError is raised.
    :param password_input:
    Is the value checked.
    :return:
    No return.
    """
    with open('CommonPassword.txt', 'r', encoding="utf-8") as file:
        for line in file:
            if password_input == line.strip():
                raise ValueError("Please select a new password, this one has been compromised")
    # Wild regex pattern
    password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$'
    if not re.search(password_pattern, password_input):
        raise ValueError("Password does not meet minimum requirements.")


def update_password(username, password):
    """
    First verifies the password, catches and raises the exception if not accepted.
    Then the password is salted and hashed, and then the password within the table is updated.
    :param username:
    :param password:
    :return:
    No return.
    """
    conn = sql.connect('userInfo.db')
    cursor = conn.cursor()

    cursor.execute('SELECT Salt, Password FROM userInfo WHERE Username=?', (username,))
    row = cursor.fetchone()

    if row is None:
        conn.close()
        raise ValueError("Username does not exist.")

    original_salt, original_password = row

    try:
        verify_password(password)
    except ValueError as exception_reason:
        conn.close()
        raise ValueError(exception_reason) from exception_reason

    password_attempt = salt_and_hash(original_salt, password)
    if password_attempt == original_password:
        conn.close()
        raise ValueError("Password cannot be your old password!")

    salt = secrets.token_hex()
    new_password = salt_and_hash(salt, password)

    cursor.execute('UPDATE userInfo SET Password=?, Salt=? WHERE Username=?', (new_password, salt, username))
    conn.commit()
    conn.close()
