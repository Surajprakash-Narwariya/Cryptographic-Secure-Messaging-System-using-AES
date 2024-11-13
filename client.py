import socket
import sqlite3
from datetime import datetime

serverIp = "127.0.0.1"
serverPort = 8080
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind((serverIp, serverPort))
serverSocket.listen(10)
conn, address = serverSocket.accept()


def setup_database():
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS messages (
                   id INTEGER PRIMARY KEY,
                   USER_ID BLOB,
                   message BLOB,
                   iv BLOB,
                   timestamp DATETIME CURRENT_TIMESTAMP)
                   """)
    conn.commit()
    conn.close()

def store_message(user_id, message, iv):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (user_id, message, iv, timestamp) VALUES(?,?,?,?)",(user_id, message, iv, datetime.now()))

    conn.commit()
    conn.close()

setup_database()