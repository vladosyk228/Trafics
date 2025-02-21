import pyshark  # Імпортуємо бібліотеку pyshark для захоплення трафіку

def categorize_traffic(packet, http_file, https_file, ftp_file, other_file):
    """
    Функція для категоризації мережевого трафіку за протоколами (HTTP, HTTPS/TLS, FTP, інший трафік)
    і збереження їх у відповідні текстові файли.
    """
    
    # Перевіряємо, чи пакет містить HTTP (незашифрований веб-трафік)
    if 'HTTP' in packet:
        http_file.write(f"{packet}\n")  # Записуємо пакет у файл HTTP
    
    # Перевіряємо, чи пакет містить TLS (зашифрований HTTPS-трафік)
    elif 'TLS' in packet:
        https_file.write(f"{packet}\n")  # Записуємо пакет у файл HTTPS
    
    # Перевіряємо, чи пакет містить FTP (файловий трафік через протокол FTP)
    elif 'FTP' in packet:
        ftp_file.write(f"{packet}\n")  # Записуємо пакет у файл FTP
    
    # Якщо пакет не належить до зазначених категорій, записуємо його в інший файл
    else:
        other_file.write(f"{packet}\n")  # Записуємо пакет у файл іншого трафіку

def capture_traffic(interface='enp2s0'):
    """
    Функція для захоплення мережевого трафіку в режимі реального часу на вказаному інтерфейсі
    """
    
    # Створюємо об'єкт для захоплення трафіку на вказаному інтерфейсі
    capture = pyshark.LiveCapture(interface=interface)
    
    # Відкриваємо файли для запису трафіку
    with open('http_traffic.txt', 'a') as http_file, \
         open('https_traffic.txt', 'a') as https_file, \
         open('ftp_traffic.txt', 'a') as ftp_file, \
         open('other_traffic.txt', 'a') as other_file:
        
        # Запускаємо безперервний процес аналізу пакетів
        for packet in capture.sniff_continuously():
            print(f"Packet captured: {packet}")  # Виводимо захоплений пакет у консоль
            categorize_traffic(packet, http_file, https_file, ftp_file, other_file)  # Викликаємо функцію для категоризації трафіку

# Головний блок виконання програми
if __name__ == "__main__":
    capture_traffic()  # Запускаємо функцію захоплення трафіку
