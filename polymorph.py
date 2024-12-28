import time
import random
import ctypes
import socket

# Функция для получения локального IP адреса
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # Получаем IP адрес через внешний сервер, чтобы избежать необходимости конфигурации
        s.connect(('10.254.254.254', 1))  
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'  # Если не удается получить реальный IP, возвращаем локальный адрес
    finally:
        s.close()
    return ip

# Установим имя процесса для диспетчера задач
try:
    import setproctitle
    setproctitle.setproctitle("IdlePythonProcess")  # Имя процесса в диспетчере задач
    print("setproctitle успешно установлен.")
except ImportError:
    print("setproctitle не установлен. Используется альтернативный метод.")
    def set_process_name(name):
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleTitleW(name)
    set_process_name("IdlePythonProcess")

# Базовый класс для полиморфного поведения
class IdleBehavior:
    def execute(self):
        pass

# Разные поведения, которые может принимать процесс
class IdleSleep(IdleBehavior):
    def execute(self):
        time.sleep(10)  # Сон для минимального использования ресурсов

class IdleLog(IdleBehavior):
    def execute(self):
        print("Программа ничего не делает")
        time.sleep(5)

class IdleRandom(IdleBehavior):
    def execute(self):
        action = random.choice(["Сон", "Лог", "Ничего"])
        if action == "Сон":
            time.sleep(2)
        elif action == "Лог":
            print("Полиморфное действие: Лог")
        else:
            pass

# Главный цикл программы
behaviors = [IdleSleep(), IdleLog(), IdleRandom()]

# Скрытый IP адрес
local_ip = get_local_ip()

# Выводим сообщение в командной строке
print(f"На компьютере работает полиморф! Он попал сюда с этого ip адреса: {local_ip}")

while True:
    behavior = random.choice(behaviors)  # Выбор случайного поведения
    behavior.execute()

