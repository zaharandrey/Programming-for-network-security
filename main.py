import socket
import ssl
import sys

# --- Етап 1: Базовий клієнт-серверний додаток з SSL/TLS ---

def start_server():
    # Налаштування SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    # Налаштування сокета
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)

    print("Сервер чекає на з'єднання...")

    # Прийом з'єднання через SSL
    with context.wrap_socket(server_socket, server_side=True) as secure_socket:
        conn, addr = secure_socket.accept()
        print(f"З'єднання встановлено з: {addr}")

        # Отримання даних
        data = conn.recv(1024).decode()
        print(f"Отримано: {data}")

        # Відправка відповіді
        conn.sendall("Дані успішно отримано".encode('utf-8'))

        conn.close()


def start_client():
    # Налаштування SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile="server.crt")

    # Підключення до сервера через SSL
    with socket.create_connection(('localhost', 12345)) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as secure_socket:
            print("Підключено до сервера")

            # Відправка даних
            secure_socket.sendall("Привіт, сервере!".encode('utf-8'))

            # Отримання відповіді
            response = secure_socket.recv(1024).decode()
            print(f"Відповідь від сервера: {response}")


# --- Етап 2: Захоплення та аналіз трафіку ---
# Для цього етапу запустіть Wireshark і фільтруйте пакети за портом 12345 (tcp.port == 12345).
# Усі дані мають бути зашифровані та недоступні у відкритому вигляді.
#
# --- Етап 3: Додаток з аутентифікацією та захистом від MITM ---
# Реалізація перевірки сертифікатів вже додана в код вище.
# Ви можете розширити функціонал:
# - Додати аутентифікацію користувачів через логін/пароль.
# - Використовувати унікальні сертифікати для кожного клієнта.

if __name__ == "__main__":
    if len(sys.argv) > 1:
        choice = sys.argv[1].strip().lower()
    else:
        print("Використовуйте: python script.py [s|c]")
        sys.exit(1)

    if choice == 's':
        start_server()
    elif choice == 'c':
        start_client()
    else:
        print("Невірний вибір!")


