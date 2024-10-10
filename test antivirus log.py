import os
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
import threading

# Пример базы данных с сигнатурами вредоносных программ (в hex)
malware_signatures = {
    "Malware1": "4d5a90000300000004000000ffff0000b8000000",
    "Malware2": "5a4d2d626f6765732d7669727573",
    "Malware3": "74657374207369676e6174757265"
}

# Функция конвертации содержимого файла в строку hex
def file_to_hex(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            return content.hex()  # Конвертируем байты в hex
    except PermissionError:
        return "[ERROR] Нет доступа к файлу: " + file_path
    except Exception as e:
        return f"[ERROR] Ошибка при чтении {file_path}: {str(e)}"

# Функция записи логов
def log_result(log_message):
    with open("scan_logs.txt", "a") as log_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_file.write(f"[{timestamp}] {log_message}\n")

# Функция сканирования файлов на наличие сигнатур вредоносного ПО
def scan_file(file_path, signatures):
    file_hex = file_to_hex(file_path)
    
    if file_hex.startswith("[ERROR]"):
        log_result(file_hex)
        return file_hex  # Возвращаем сообщение об ошибке

    for name, signature in signatures.items():
        if signature in file_hex:
            log_message = f"[ALERT] {name} обнаружен в {file_path}"
            log_result(log_message)
            return log_message
    
    log_message = f"[OK] Угроз не обнаружено в {file_path}"
    log_result(log_message)
    return log_message

# Функция рекурсивного сканирования директорий
def scan_directory(directory_path, signatures, result_text):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            result = scan_file(file_path, signatures)
            result_text.insert(tk.END, result + "\n")
            result_text.update_idletasks()  # Обновляем интерфейс для отображения результата

# Функция для запуска сканирования в отдельном потоке
def scan_directory_thread(directory_path, signatures, result_text):
    threading.Thread(target=scan_directory, args=(directory_path, signatures, result_text)).start()

# Функция для сканирования всего диска C: в отдельном потоке
def scan_full_disk():
    directory_path = "C:/"  # Указываем путь к диску C:
    if os.path.exists(directory_path):
        result_text.insert(tk.END, f"Сканирование диска {directory_path} началось...\n")
        scan_directory_thread(directory_path, malware_signatures, result_text)
    else:
        messagebox.showwarning("Ошибка", f"Диск {directory_path} не найден!")

# Функция выбора и сканирования одного файла
def scan_single_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        result = scan_file(file_path, malware_signatures)
        result_text.insert(tk.END, result + "\n")
    else:
        messagebox.showwarning("Выбор файла", "Файл не выбран!")

# Функция выбора и сканирования директории
def scan_directory_gui():
    directory_path = filedialog.askdirectory()
    if directory_path:
        result_text.insert(tk.END, f"Сканирование директории {directory_path} началось...\n")
        scan_directory_thread(directory_path, malware_signatures, result_text)
    else:
        messagebox.showwarning("Выбор директории", "Директория не выбрана!")

# Создание основного окна
root = tk.Tk()
root.title("Best Antivirus Ever")
root.geometry("600x400")

# Метка
label = tk.Label(root, text="Best Antivirus Ever", font=("Arial", 16))
label.pack(pady=10)

# Кнопка для сканирования файла
scan_file_button = tk.Button(root, text="Сканировать файл", command=scan_single_file, font=("Arial", 12))
scan_file_button.pack(pady=5)

# Кнопка для сканирования директории
scan_directory_button = tk.Button(root, text="Сканировать директорию", command=scan_directory_gui, font=("Arial", 12))
scan_directory_button.pack(pady=5)

# Кнопка для сканирования всего диска C:
scan_full_disk_button = tk.Button(root, text="Сканировать диск C:", command=scan_full_disk, font=("Arial", 12))
scan_full_disk_button.pack(pady=5)

# Поле для вывода результатов
result_text = tk.Text(root, height=15, width=70)
result_text.pack(pady=10)

# Скроллбар для текстового поля
scrollbar = tk.Scrollbar(root)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
result_text.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=result_text.yview)

# Запуск основного цикла
root.mainloop()
