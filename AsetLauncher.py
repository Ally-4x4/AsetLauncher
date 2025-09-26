import requests  # For fetching Mojang manifest
import subprocess
from uuid import uuid1
import uuid as _uuid
import hashlib
from random_username.generate import generate_username
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QIcon
import os
import json
import bcrypt  # Импортируем bcrypt
import time
import sys
import webbrowser  # Для открытия папки Minecraft
from functools import partial # Import partial
import logging  # Импортируем модуль логирования
import zipfile
from PyQt5.QtWidgets import QFileDialog, QMessageBox
import shutil
import threading  # Импортируем threading
import concurrent.futures  # Импортируем для многопоточной загрузки
import ctypes
import re
from PyQt5.QtCore import QPropertyAnimation, QEasingCurve, QRect, pyqtSignal
from PyQt5.QtWidgets import QScrollArea, QFrame
def get_total_ram_gb():
    try:
        import ctypes
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        return max(0, int(stat.ullTotalPhys // (1024**3)))
    except Exception:
        return 8

# Настройка логирования - более подробные логи для отслеживания процессов загрузки, установки и запуска
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'logs', 'launcher.log'), encoding='utf-8')
    ]
)
# Отключаем debug логи для urllib3 и requests, но оставляем INFO
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.INFO)

# Вспомогатель для корректного позиционирования кастомной кнопки закрытия поверх контента
class _CloseButtonHelper(QtCore.QObject):
    def __init__(self, host_widget, button, margin=5):
        super().__init__(host_widget)
        self.host_widget = host_widget
        self.button = button
        self.margin = margin

    def eventFilter(self, obj, event):
        if obj is self.host_widget and event.type() == QtCore.QEvent.Resize:
            try:
                w = self.host_widget.width()
                self.button.move(w - self.button.width() - self.margin, self.margin)
                self.button.raise_()
            except Exception:
                pass
        return False

def attach_close_button(host_widget, button, margin=5):
    helper = _CloseButtonHelper(host_widget, button, margin)
    host_widget.installEventFilter(helper)
    # Храним ссылку, чтобы helper не был собран GC
    setattr(host_widget, "_close_button_helper", helper)

# Глобальные настройки и кэш
DEFAULT_HTTP_TIMEOUT = 10
_MOJANG_MANIFEST_CACHE = None

# Функция для получения директории Minecraft
def get_minecraft_directory():
    return os.path.expanduser("~/.minecraft_asetlauncher")

minecraft_directory = get_minecraft_directory()

# Устанавливаем базовый путь для всех ресурсов лаунчера
if getattr(sys, 'frozen', False):
    # Если приложение упаковано в .exe
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Если приложение запускается из исходного кода
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Обновляем пути к файлам
IMAGES_DIR = os.path.join(BASE_DIR, 'build', 'images')
LAUNCHER_FILES_DIR = os.path.join(BASE_DIR, 'build', 'Launcher_Files')
RESOURCE_PACKS_DIR = os.path.join(BASE_DIR, 'build', 'Resourse_packs')
AVATARS_DIR = os.path.join(IMAGES_DIR, 'avatars')

# Обновляем путь к файлу аккаунтов
ACCOUNTS_FILE = os.path.join(LAUNCHER_FILES_DIR, "accounts.json")
# Бэкенд сайта AsetLauncher для авторизации и сессий
BACKEND_BASE_URL = "http://89.250.150.135:5500"
AUTH_ENDPOINT = BACKEND_BASE_URL + "/authserver/authenticate"
REFRESH_ENDPOINT = BACKEND_BASE_URL + "/authserver/refresh"
VALIDATE_ENDPOINT = BACKEND_BASE_URL + "/authserver/validate"
PROFILE_SETTINGS_FILE = os.path.join(LAUNCHER_FILES_DIR, "profile_settings.json")
FRIENDS_FILE = os.path.join(LAUNCHER_FILES_DIR, "friends.json")
FRIENDS_AVATARS_DIR = os.path.join(LAUNCHER_FILES_DIR, "friends_avatars")

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
REDIRECTS = [
    "89.250.150.135 authserver.mojang.com",
    "89.250.150.135 sessionserver.mojang.com",
    # Остальные сервисы Mojang не трогаем
]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def add_hosts_redirects():
    logging.info("🔧 Начинаем изменение hosts файла...")
    logging.info(f"Проверка прав администратора: {is_admin()}")
    
    if not is_admin():
        logging.warning("❌ Для изменения hosts-файла нужны права администратора!")
        return False
    
    try:
        logging.info(f"📂 Пытаемся открыть hosts файл: {HOSTS_PATH}")
        
        # Читаем текущее содержимое
        try:
            with open(HOSTS_PATH, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            # Fallback на ANSI кодировку если UTF-8 не работает
            with open(HOSTS_PATH, "r", encoding="cp1251") as f:
                content = f.read()
        
        logging.info(f"📄 Hosts файл прочитан, размер: {len(content)} символов")
        
        # Проверяем какие строки нужно добавить
        lines_to_add = []
        for redirect in REDIRECTS:
            # Более надежная проверка - ищем IP и домен отдельно
            ip_part = redirect.split()[0]  # 89.250.150.135
            domain_part = redirect.split()[1]  # authserver.mojang.com
            
            if ip_part in content and domain_part in content:
                logging.info(f"✅ Уже есть: {redirect}")
            else:
                lines_to_add.append(redirect)
                logging.info(f"➕ Нужно добавить: {redirect}")
                logging.info(f"   IP {ip_part} в файле: {ip_part in content}")
                logging.info(f"   Домен {domain_part} в файле: {domain_part in content}")
        
        # Добавляем новые строки если нужно
        if lines_to_add:
            try:
                with open(HOSTS_PATH, "a", encoding="utf-8") as f:
                    for line in lines_to_add:
                        f.write("\n" + line)
                        logging.info(f"📝 Записана строка: {line}")
                    f.flush()  # Принудительная запись
                logging.info(f"✅ Добавлено {len(lines_to_add)} строк в hosts файл")
                
                # Проверяем что записалось
                with open(HOSTS_PATH, "r", encoding="utf-8") as f:
                    new_content = f.read()
                    for line in lines_to_add:
                        if line in new_content:
                            logging.info(f"✅ Подтверждена запись: {line}")
                        else:
                            logging.error(f"❌ НЕ НАЙДЕНА в файле: {line}")
                            
            except PermissionError as e:
                logging.error(f"❌ Ошибка доступа при записи hosts: {e}")
                return False
            except Exception as e:
                logging.error(f"❌ Ошибка записи hosts: {e}")
                return False
        else:
            logging.info("✅ Все необходимые перенаправления уже настроены")
        
        return True
        
    except Exception as e:
        logging.error(f"❌ Ошибка при изменении hosts-файла: {e}")
        logging.error(f"❌ Тип ошибки: {type(e).__name__}")
        return False

def remove_hosts_redirects():
    if not is_admin():
        logging.warning("Для изменения hosts-файла нужны права администратора!")
        return
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        with open(HOSTS_PATH, "w", encoding="utf-8") as f:
            for line in lines:
                if not any(domain in line for domain in [
                    "authserver.mojang.com",
                    "sessionserver.mojang.com",
                    "api.minecraftservices.com",
                    "services.minecraft.net",
                    "account.mojang.com"
                ]):
                    f.write(line)
        logging.info("Строки для обхода авторизации удалены из hosts-файла.")
    except Exception as e:
        logging.error(f"Ошибка при изменении hosts-файла: {e}")

def register_account(username, password):
    """Регистрирует новый аккаунт."""
    # Проверяем, есть ли уже аккаунт
    if load_accounts():
        logging.warning("Аккаунт уже существует, регистрация невозможна.")
        return False

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    accounts = [{"username": username, "password": hashed_password.decode('utf-8')}]
    save_accounts(accounts)
    return True

def _save_authenticated_account(nickname, access_token, client_token, uuid_no_dashes):
    # Сохраняем один активный аккаунт с токенами
    data = [{
        "username": nickname,
        "accessToken": access_token,
        "clientToken": client_token,
        "uuid": uuid_no_dashes,
    }]
    save_accounts(data)


def _backend_authenticate(username, password):
    try:
        payload = {
            "username": username,
            "password": password,
            # clientToken опционален; бэкенд создаст, если не указан
        }
        r = requests.post(AUTH_ENDPOINT, json=payload, timeout=10)
        if r.status_code != 200:
            return None
        d = r.json()
        access_token = d.get("accessToken")
        client_token = d.get("clientToken")
        prof = d.get("selectedProfile") or {}
        uuid_no_dashes = prof.get("id")
        name = prof.get("name") or username
        if access_token and client_token and uuid_no_dashes:
            _save_authenticated_account(name, access_token, client_token, uuid_no_dashes)
            return {
                "username": name,
                "accessToken": access_token,
                "clientToken": client_token,
                "uuid": uuid_no_dashes,
            }
    except Exception as e:
        logging.error(f"Ошибка обращения к бекенду авторизации: {e}")
    return None


def login_account(username, password):
    """Авторизация через бэкенд. Возвращает True при успехе."""
    auth = _backend_authenticate(username, password)
    return bool(auth)

def delete_account():
    """Удаляет аккаунт."""
    save_accounts([])  # Сохраняем пустой список
    logging.info("Аккаунт удален.")
    return True

def load_accounts():
    """Загружает аккаунты из файла."""
    try:
        with open(ACCOUNTS_FILE, "r") as f:
            accounts = json.load(f)
            # Убедимся, что у нас не больше одного аккаунта
            if len(accounts) > 1:
                logging.warning("Обнаружено несколько аккаунтов. Используется только первый.")
                return [accounts[0]]
            return accounts
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_accounts(accounts):
    """Сохраняет аккаунты в файл."""
    # Ensure the directory exists before saving the file
    os.makedirs(LAUNCHER_FILES_DIR, exist_ok=True)

    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(accounts, f)

def load_friends():
    """Загружает список друзей из файла."""
    try:
        with open(FRIENDS_FILE, "r", encoding="utf-8") as f:
            friends = json.load(f)
            if isinstance(friends, list):
                return friends
            return []
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_friends(friends):
    """Сохраняет список друзей в файл."""
    os.makedirs(LAUNCHER_FILES_DIR, exist_ok=True)
    with open(FRIENDS_FILE, "w", encoding="utf-8") as f:
        json.dump(friends, f, ensure_ascii=False)

def clear_saved_accounts():
    """Очищает сохраненные аккаунты"""
    try:
        if os.path.exists(ACCOUNTS_FILE):
            os.remove(ACCOUNTS_FILE)
            logging.info("Старые аккаунты очищены")
    except Exception as e:
        logging.error(f"Ошибка очистки аккаунтов: {e}")

def sync_token_with_backend():
    """Синхронизирует токен лаунчера с backend для API друзей"""
    try:
        accounts = load_accounts()
        if not accounts or not accounts[0].get('accessToken'):
            return False
            
        account = accounts[0]
        access_token = account.get('accessToken')
        client_token = account.get('clientToken')
        
        if not access_token or not client_token:
            return False
            
        # Отправляем запрос на синхронизацию
        session = requests.Session()
        data = {
            'access_token': access_token,
            'client_token': client_token
        }
        response = session.post(f"{BACKEND_BASE_URL}/api/auth/sync-token", json=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                return True
        elif response.status_code == 404:
            # Токен не найден в device_codes - значит нужна переавторизация
            return "reauth_required"
        
        return False
        
    except Exception as e:
        logging.error(f"Ошибка синхронизации токена: {e}")
        return False

def get_auth_headers(auto_sync_on_fail=True):
    """Получает заголовки авторизации для API запросов"""
    try:
        accounts = load_accounts()
        if accounts and len(accounts) > 0:
            # Берем первый аккаунт (у нас всегда один активный аккаунт)
            current_account = accounts[0]
            if current_account and current_account.get('accessToken'):
                token = current_account["accessToken"]
                return {'Authorization': f'Bearer {token}'}
        logging.warning("Нет авторизованного аккаунта для API запросов")
    except Exception as e:
        logging.error(f"Ошибка получения заголовков авторизации: {e}")
    return {}

def fetch_profile_by_uuid(friend_uuid):
    """Запрашивает профиль игрока по UUID на бэкенде и возвращает dict {username, uuid, avatar_url?}.
    Ожидается, что бэкенд предоставит конечную точку /api/profile/<uuid>.
    """
    try:
        url = f"{BACKEND_BASE_URL}/api/profile/{friend_uuid}"
        r = requests.get(url, timeout=10)
        if not r.ok:
            return None
        d = r.json()
        # Унифицируем ключи
        return {
            "username": d.get("username") or d.get("name"),
            "uuid": d.get("uuid") or d.get("id") or friend_uuid,
            "avatar_url": d.get("avatar_url") or d.get("avatar")
        }
    except Exception:
        return None

def download_avatar(url, uuid_str):
    """Скачивает аватар друга в локальную папку и возвращает путь, либо None."""
    try:
        if not url:
            return None
        os.makedirs(FRIENDS_AVATARS_DIR, exist_ok=True)
        local_path = os.path.join(FRIENDS_AVATARS_DIR, f"{uuid_str}.png")
        resp = requests.get(url, timeout=10)
        if resp.ok:
            with open(local_path, "wb") as f:
                f.write(resp.content)
            return local_path
    except Exception:
        pass
    return None

class LoginDialog(QtWidgets.QDialog):
    def __init__(self, main_window, ui):  # Передаём ссылку на Ui_MainWindow
        super().__init__()
        self.main_window = main_window
        self.ui = ui
        self.setWindowTitle("Вход / Регистрация")
        self.setModal(True)
        self.setFixedSize(300, 250)  # Меньший размер окна
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")
        # Кнопка закрытия (как в главном меню)
        try:
            self.close_btn = QtWidgets.QPushButton(self)
            self.close_btn.setFixedSize(25, 25)
            self.close_btn.setStyleSheet("""
                QPushButton { background-color:rgba(68,71,90,0); color:#ffffff; border:none; border-radius:4px; }
                QPushButton:hover { background-color:rgb(250,44,61); }
            """)
            close_icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Close.png"))
            self.close_btn.setIcon(close_icon)
            self.close_btn.setIconSize(QtCore.QSize(25, 25))
            self.close_btn.clicked.connect(self.close)
            attach_close_button(self, self.close_btn, margin=5)
        except Exception:
            pass

        self.username_label = QtWidgets.QLabel("Ник:")
        self.username_input = QtWidgets.QLineEdit()
        self.username_input.setMaxLength(20)
        self.password_label = QtWidgets.QLabel("Пароль:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setMaxLength(20)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.show_password_button = QtWidgets.QPushButton("Показать", self)
        self.show_password_button.setCheckable(True)  # Кнопка-переключатель
        self.show_password_button.clicked.connect(self.toggle_password_visibility)

        # Устанавливаем стили для полей ввода
        self.username_input.setStyleSheet("background-color: #44475a; color: #ffffff; border: none; border-radius: 4px; padding: 3px;")
        self.password_input.setStyleSheet("background-color: #44475a; color: #ffffff; border: none; border-radius: 4px; padding: 3px;")

        self.login_button = QtWidgets.QPushButton("Авторизовать через сайт")
        self.register_button = QtWidgets.QPushButton("Зарегистрироваться")
        self.delete_button = QtWidgets.QPushButton("Удалить аккаунт")

        # Устанавливаем стили для кнопок
        button_style = """
            QPushButton {
                background-color: #61afef;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #508acc;
            }
        """
        self.login_button.setStyleSheet(button_style)
        self.register_button.setStyleSheet(button_style)
        self.delete_button.setStyleSheet(button_style)
        self.show_password_button.setStyleSheet(button_style)  # Применяем стиль к кнопке просмотра пароля

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)

        # Layout для пароля и кнопки "Показать"
        password_layout = QtWidgets.QHBoxLayout()
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(self.show_password_button)
        layout.addLayout(password_layout)  # Добавляем этот layout в основной

        layout.addWidget(self.login_button)

        # Если аккаунт уже существует, показываем кнопку удаления, иначе - регистрации
        if load_accounts():
            layout.addWidget(self.delete_button)
            self.register_button.hide()
        else:
            layout.addWidget(self.register_button)
            self.delete_button.hide()

        self.setLayout(layout)

        self.login_button.clicked.connect(self.login)
        self.register_button.clicked.connect(self.register)
        self.delete_button.clicked.connect(self.delete)

        # Инициализируем позицию и Z-порядок кнопки закрытия поверх лэйаута
        try:
            if hasattr(self, 'close_btn') and self.close_btn is not None:
                self.close_btn.move(self.width() - self.close_btn.width() - 5, 5)
                self.close_btn.raise_()
        except Exception:
            pass

    def toggle_password_visibility(self):
        if self.show_password_button.isChecked():
            self.password_input.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.show_password_button.setText("Скрыть")
        else:
            self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
            self.show_password_button.setText("Показать")

    def login(self):
        try:
            # Device flow: получаем код на бекенде и открываем браузер
            r = requests.post(BACKEND_BASE_URL + '/api/device/start', timeout=10)
            d = r.json()
            verify_url = d.get('verification_uri')
            device_code = d.get('device_code')
            if not verify_url or not device_code:
                QtWidgets.QMessageBox.warning(self, "Ошибка", "Не удалось начать авторизацию.")
                return
            import webbrowser
            webbrowser.open(verify_url)
            # Пулинг подтверждения
            for _ in range(200):  # ~10 минут с интервалом 3с
                time.sleep(3)
                pr = requests.post(BACKEND_BASE_URL + '/api/device/poll', json={'device_code': device_code}, timeout=10)
                if pr.status_code == 202:
                    continue
                pd = pr.json()
                if pr.ok and pd.get('ok'):
                    # Сохраняем токены локально и закрываем диалог
                    _save_authenticated_account(pd['username'], pd['accessToken'], pd['clientToken'], pd['uuid'])
                    self.main_window.last_login_time = time.time()
                    self.accept()
                    return
                else:
                    QtWidgets.QMessageBox.warning(self, "Ошибка", pd.get('message','Не удалось авторизоваться.'))
                    return
            QtWidgets.QMessageBox.warning(self, "Таймаут", "Время ожидания подтверждения истекло.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Ошибка", f"{e}")

    def register(self):
        import webbrowser
        webbrowser.open(BACKEND_BASE_URL + '/register.html')

    def delete(self):
        reply = QtWidgets.QMessageBox.question(self, 'Удаление аккаунта',
                                                   "Вы уверены, что хотите удалить аккаунт?",
                                                   QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)

        if reply == QtWidgets.QMessageBox.Yes:
            if delete_account():
                QtWidgets.QMessageBox.information(self, "Удаление аккаунта", "Аккаунт успешно удален.")
                # Обновляем интерфейс после удаления
                self.main_window.show_login_dialog()
                self.close()

class ProfileDialog(QtWidgets.QDialog):
    def __init__(self, main_window, ui):
        super().__init__()
        self.main_window = main_window
        self.ui = ui
        self.setWindowTitle("Настройки профиля")
        self.setModal(True)
        self.setFixedSize(300, 280)  # Увеличиваем высоту для кнопки выхода
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")
        # Кнопка закрытия
        try:
            self.close_btn = QtWidgets.QPushButton(self)
            self.close_btn.setFixedSize(25, 25)
            self.close_btn.setStyleSheet("""
                QPushButton { background-color:rgba(68,71,90,0); color:#ffffff; border:none; border-radius:4px; }
                QPushButton:hover { background-color:rgb(250,44,61); }
            """)
            close_icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Close.png"))
            self.close_btn.setIcon(close_icon)
            self.close_btn.setIconSize(QtCore.QSize(25, 25))
            self.close_btn.clicked.connect(self.close)
            attach_close_button(self, self.close_btn, margin=5)
        except Exception:
            pass

        self.current_username = ""
        accounts = load_accounts()
        if accounts:
            self.current_username = accounts[0]["username"]

        # Add a QLabel for the skin head
        self.skin_head_label = QtWidgets.QLabel(self)
        self.skin_head_label.setAlignment(QtCore.Qt.AlignCenter)
        self.update_skin_head()

        # Add username label under skin head
        self.username_label = QtWidgets.QLabel(self)
        self.username_label.setAlignment(QtCore.Qt.AlignCenter)
        self.username_label.setStyleSheet("color:#ffffff; font-size:14px; font-weight:600;")
        self.update_username_label()

        # Новые кнопки
        self.account_data_button = QtWidgets.QPushButton("Аккаунт")
        # self.skin_settings_button = QtWidgets.QPushButton("Настройки скина")  # Скины удалены
        self.profile_avatars_button = QtWidgets.QPushButton("Аватары профиля")
        self.logout_button = QtWidgets.QPushButton("Выйти из аккаунта")

        button_style = """
            QPushButton {
                background-color: #61afef;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #508acc;
            }
        """
        self.account_data_button.setStyleSheet(button_style)
        # self.skin_settings_button.setStyleSheet(button_style)  # Скины удалены
        self.profile_avatars_button.setStyleSheet(button_style)
        
        # Стиль для кнопки выхода (красный)
        logout_style = """
            QPushButton {
                background-color: #e06c75;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #c86470;
            }
        """
        self.logout_button.setStyleSheet(logout_style)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.skin_head_label)
        layout.addWidget(self.username_label)
        layout.addWidget(self.account_data_button)
        # layout.addWidget(self.skin_settings_button)  # Скины удалены
        layout.addWidget(self.profile_avatars_button)
        layout.addWidget(self.logout_button)

        self.setLayout(layout)

        self.account_data_button.clicked.connect(self.open_account_data_dialog)
        # self.skin_settings_button.clicked.connect(self.open_skin_settings)  # Скины удалены
        self.profile_avatars_button.clicked.connect(self.open_avatar_selection)
        self.logout_button.clicked.connect(self.logout_account)

    def update_skin_head(self):
        # Используем дефолтный аватар вместо скинов
        try:
            default_avatar = QtGui.QPixmap(os.path.join(IMAGES_DIR, "profile-icon.png"))
            if not default_avatar.isNull():
                scaled_avatar = default_avatar.scaled(64, 64, QtCore.Qt.KeepAspectRatio, QtCore.Qt.FastTransformation)
                self.skin_head_label.setPixmap(scaled_avatar)
            else:
                self.skin_head_label.setText("👤")
        except Exception:
            self.skin_head_label.setText("👤")

    def update_username_label(self):
        accounts = load_accounts()
        if accounts:
            self.username_label.setText(accounts[0]["username"])
        else:
            self.username_label.setText("Аккаунт не найден")

    def open_change_nickname_dialog(self):
        dialog = ChangeNicknameDialog(self.main_window, self)
        dialog.exec_()

    def open_change_password_dialog(self):
        dialog = ChangePasswordDialog(self.main_window, self)
        dialog.exec_()

    def open_skin_settings(self):
        # Скины удалены
        QtWidgets.QMessageBox.information(self, "Информация", "Функция скинов удалена")

    def open_account_data_dialog(self):
        dlg = AccountDataDialog(self.main_window, self.ui)
        dlg.exec_()

    def open_avatar_selection(self):
        dlg = AvatarSelectionDialog(self.main_window, self.ui)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            try:
                self.ui.apply_profile_avatar_icon()
            except Exception:
                pass
    
    def logout_account(self):
        """Выход из аккаунта через диалог профиля"""
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Question)
        msg.setWindowTitle("Выход из аккаунта")
        msg.setText("Вы уверены, что хотите выйти из аккаунта?\n\nЭто потребует повторной авторизации для запуска игры и использования системы друзей.")
        msg.addButton("Выйти", QtWidgets.QMessageBox.AcceptRole)
        msg.addButton("Отмена", QtWidgets.QMessageBox.RejectRole)
        
        result = msg.exec_()
        if result == 0:  # Выйти
            # Вызываем метод logout_account из главного окна
            self.ui.logout_account()
            # Закрываем диалог профиля
            self.accept()

class ChangeNicknameDialog(QtWidgets.QDialog):  # Диалог смены ника
    def __init__(self, main_window, ui):
        super().__init__()
        self.main_window = main_window
        self.ui = ui
        self.setWindowTitle("Сменить ник")
        self.setModal(True)
        self.setFixedSize(300, 150)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")
        # Кнопка закрытия
        try:
            self.close_btn = QtWidgets.QPushButton(self)
            self.close_btn.setFixedSize(25, 25)
            self.close_btn.setStyleSheet("""
                QPushButton { background-color:rgba(68,71,90,0); color:#ffffff; border:none; border-radius:4px; }
                QPushButton:hover { background-color:rgb(250,44,61); }
            """)
            close_icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Close.png"))
            self.close_btn.setIcon(close_icon)
            self.close_btn.setIconSize(QtCore.QSize(25, 25))
            self.close_btn.clicked.connect(self.close)
            attach_close_button(self, self.close_btn, margin=5)
        except Exception:
            pass

        self.new_username_label = QtWidgets.QLabel("Новый ник:")
        self.new_username_input = QtWidgets.QLineEdit()
        self.new_username_input.setMaxLength(20)

        # Стиль для полей ввода
        input_style = "background-color: #44475a; color: #ffffff; border: none; border-radius: 4px; padding: 3px;"
        self.new_username_input.setStyleSheet(input_style)

        self.save_button = QtWidgets.QPushButton("Сохранить")
        self.cancel_button = QtWidgets.QPushButton("Отмена")

        # Стиль для кнопок
        button_style = """
            QPushButton {
                background-color: #61afef;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #508acc;
            }
        """
        self.save_button.setStyleSheet(button_style)
        self.cancel_button.setStyleSheet(button_style)

        self.error_label = QtWidgets.QLabel("")
        self.error_label.setStyleSheet("color: red;")
        self.error_label.setAlignment(QtCore.Qt.AlignCenter)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.new_username_label)
        layout.addWidget(self.new_username_input)
        layout.addWidget(self.error_label)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.save_button.clicked.connect(self.save_changes)
        self.cancel_button.clicked.connect(self.reject)

    def save_changes(self):
        new_username = self.new_username_input.text()

        if not new_username:
            self.error_label.setText("Пожалуйста, введите новый ник.")
            return

        if len(new_username) > 20:
            self.error_label.setText("Ник не может быть длиннее 20 символов.")
            return

        accounts = load_accounts()
        if accounts:
            accounts[0]["username"] = new_username
            save_accounts(accounts)
            self.error_label.setText("Ник успешно изменен.")
            self.accept()
            # Отображение ника перенесено в диалог профиля
        else:
            self.error_label.setText("Аккаунт не найден.")

class ChangePasswordDialog(QtWidgets.QDialog):  # Диалог смены пароля
    def __init__(self, main_window, ui):
        super().__init__()
        self.main_window = main_window
        self.ui = ui
        self.setWindowTitle("Сменить пароль")
        self.setModal(True)
        self.setFixedSize(300, 200)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")
        try:
            self.close_btn = QtWidgets.QPushButton(self)
            self.close_btn.setFixedSize(25, 25)
            self.close_btn.setStyleSheet("""
                QPushButton { background-color:rgba(68,71,90,0); color:#ffffff; border:none; border-radius:4px; }
                QPushButton:hover { background-color:rgb(250,44,61); }
            """)
            close_icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Close.png"))
            self.close_btn.setIcon(close_icon)
            self.close_btn.setIconSize(QtCore.QSize(25, 25))
            self.close_btn.clicked.connect(self.close)
            attach_close_button(self, self.close_btn, margin=5)
        except Exception:
            pass

        self.password_label = QtWidgets.QLabel("Новый пароль:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setMaxLength(20)
        self.password_input.setStyleSheet("background-color: #44475a; color: #ffffff; border: none; border-radius: 4px; padding: 3px;")
        self.save_button = QtWidgets.QPushButton("Сохранить")
        self.save_button.setStyleSheet("""
            QPushButton { background-color: #61afef; color: #ffffff; border: none; border-radius: 4px; padding: 5px 10px; font-size: 12px; }
            QPushButton:hover { background-color: #508acc; }
        """)
        self.error_label = QtWidgets.QLabel("")
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.save_button)
        layout.addWidget(self.error_label)
        self.setLayout(layout)
        self.save_button.clicked.connect(self.save_new_password)

    def save_new_password(self):
        new_password = self.password_input.text()
        if not new_password:
            self.error_label.setText("Введите новый пароль.")
            return
        if len(new_password) > 20:
            self.error_label.setText("Пароль не может быть длиннее 20 символов.")
            return
        accounts = load_accounts()
        if accounts:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            accounts[0]["password"] = hashed_password.decode('utf-8')
            save_accounts(accounts)
            self.error_label.setText("Пароль успешно изменен.")
            self.accept()
        else:
            self.error_label.setText("Аккаунт не найден.")

class AccountDataDialog(QtWidgets.QDialog):
    def __init__(self, main_window, ui):
        super().__init__()
        self.main_window = main_window
        self.ui = ui
        self.setWindowTitle("Данные аккаунта")
        self.setModal(True)
        self.setFixedSize(320, 220)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")
        # Кнопка закрытия
        try:
            self.close_btn = QtWidgets.QPushButton(self)
            self.close_btn.setFixedSize(25, 25)
            self.close_btn.setStyleSheet("""
                QPushButton { background-color:rgba(68,71,90,0); color:#ffffff; border:none; border-radius:4px; }
                QPushButton:hover { background-color:rgb(250,44,61); }
            """)
            close_icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Close.png"))
            self.close_btn.setIcon(close_icon)
            self.close_btn.setIconSize(QtCore.QSize(25, 25))
            self.close_btn.clicked.connect(self.close)
            attach_close_button(self, self.close_btn, margin=5)
        except Exception:
            pass

        self.change_nickname_button = QtWidgets.QPushButton("Сменить ник")
        self.change_password_button = QtWidgets.QPushButton("Сменить пароль")
        button_style = """
            QPushButton { background-color: #61afef; color: #ffffff; border: none; border-radius: 4px; padding: 5px 10px; font-size: 12px; }
            QPushButton:hover { background-color: #508acc; }
        """
        self.change_nickname_button.setStyleSheet(button_style)
        self.change_password_button.setStyleSheet(button_style)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.change_nickname_button)
        layout.addWidget(self.change_password_button)
        self.setLayout(layout)

        self.change_nickname_button.clicked.connect(self.open_change_nickname_dialog)
        self.change_password_button.clicked.connect(self.open_change_password_dialog)

    def open_change_nickname_dialog(self):
        dialog = ChangeNicknameDialog(self.main_window, self.ui)
        dialog.exec_()

    def open_change_password_dialog(self):
        dialog = ChangePasswordDialog(self.main_window, self.ui)
        dialog.exec_()

class AvatarSelectionDialog(QtWidgets.QDialog):
    def __init__(self, main_window, ui):
        super().__init__()
        self.main_window = main_window
        self.ui = ui
        self.setWindowTitle("Аватары профиля")
        self.setModal(True)
        self.setFixedSize(400, 260)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")
        # Кнопка закрытия
        try:
            self.close_btn = QtWidgets.QPushButton(self)
            self.close_btn.setFixedSize(25, 25)
            self.close_btn.setStyleSheet("""
                QPushButton { background-color:rgba(68,71,90,0); color:#ffffff; border:none; border-radius:4px; }
                QPushButton:hover { background-color:rgb(250,44,61); }
            """)
            close_icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Close.png"))
            self.close_btn.setIcon(close_icon)
            self.close_btn.setIconSize(QtCore.QSize(25, 25))
            self.close_btn.clicked.connect(self.close)
            attach_close_button(self, self.close_btn, margin=5)
        except Exception:
            pass

        # Три аватара в ряд с кнопками "Выбрать"
        names = [
            ("Крипер_няша", os.path.join(AVATARS_DIR, "Крипер_няша.png")),
            ("Классика", os.path.join(AVATARS_DIR, "Классика.png")),
            ("Стандарт", os.path.join(AVATARS_DIR, "Стандарт.png")),
        ]

        grid = QtWidgets.QGridLayout()
        for idx, (title, path) in enumerate(names):
            col = idx
            # Изображение
            img_label = QtWidgets.QLabel()
            img_label.setAlignment(QtCore.Qt.AlignCenter)
            if os.path.exists(path):
                pix = QtGui.QPixmap(path).scaled(96, 96, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
                img_label.setPixmap(pix)
            else:
                img_label.setText(title)
            grid.addWidget(img_label, 0, col)
            # Кнопка Выбрать
            btn = QtWidgets.QPushButton("Выбрать")
            btn.setStyleSheet("""
                QPushButton { background-color: #61afef; color: #ffffff; border: none; border-radius: 4px; padding: 5px 10px; }
                QPushButton:hover { background-color: #508acc; }
            """)
            btn.clicked.connect(lambda _, p=path: self.choose_avatar(p))
            grid.addWidget(btn, 1, col)

        root = QtWidgets.QVBoxLayout()
        root.addLayout(grid)
        self.setLayout(root)

    def choose_avatar(self, path):
        try:
            settings = {}
            if os.path.exists(PROFILE_SETTINGS_FILE):
                with open(PROFILE_SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
            settings['profile_avatar_path'] = path
            os.makedirs(LAUNCHER_FILES_DIR, exist_ok=True)
            with open(PROFILE_SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(settings, f, ensure_ascii=False)
        except Exception:
            pass
        self.accept()
    def __init__password_dialog(self, main_window, ui):
        super().__init__()
        self.main_window = main_window
        self.ui = ui
        self.setWindowTitle("Сменить пароль")
        self.setModal(True)
        self.setFixedSize(300, 200)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")
        # Кнопка закрытия
        try:
            self.close_btn = QtWidgets.QPushButton(self)
            self.close_btn.setFixedSize(25, 25)
            self.close_btn.setStyleSheet("""
                QPushButton { background-color:rgba(68,71,90,0); color:#ffffff; border:none; border-radius:4px; }
                QPushButton:hover { background-color:rgb(250,44,61); }
            """)
            close_icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Close.png"))
            self.close_btn.setIcon(close_icon)
            self.close_btn.setIconSize(QtCore.QSize(25, 25))
            self.close_btn.clicked.connect(self.close)
            attach_close_button(self, self.close_btn, margin=5)
        except Exception:
            pass

        self.new_password_label = QtWidgets.QLabel("Новый пароль:")
        self.new_password_input = QtWidgets.QLineEdit()
        self.new_password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.new_password_input.setMaxLength(20)

        self.confirm_password_label = QtWidgets.QLabel("Подтвердите пароль:")
        self.confirm_password_input = QtWidgets.QLineEdit()
        self.confirm_password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirm_password_input.setMaxLength(20)

        # Стиль для полей ввода
        input_style = "background-color: #44475a; color: #ffffff; border: none; border-radius: 4px; padding: 3px;"
        self.new_password_input.setStyleSheet(input_style)
        self.confirm_password_input.setStyleSheet(input_style)

        self.save_button = QtWidgets.QPushButton("Сохранить")
        self.cancel_button = QtWidgets.QPushButton("Отмена")

        # Стиль для кнопок
        button_style = """
            QPushButton {
                background-color: #61afef;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #508acc;
            }
        """
        self.save_button.setStyleSheet(button_style)
        self.cancel_button.setStyleSheet(button_style)

        self.error_label = QtWidgets.QLabel("")
        self.error_label.setStyleSheet("color: red;")
        self.error_label.setAlignment(QtCore.Qt.AlignCenter)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.new_password_label)
        layout.addWidget(self.new_password_input)
        layout.addWidget(self.confirm_password_label)
        layout.addWidget(self.confirm_password_input)
        layout.addWidget(self.error_label)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.save_button.clicked.connect(self.save_changes)
        self.cancel_button.clicked.connect(self.reject)

    def save_changes(self):
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_password_input.text()

        if not new_password or not confirm_password:
            self.error_label.setText("Пожалуйста, заполните все поля.")
            return

        if new_password != confirm_password:
            self.error_label.setText("Пароли не совпадают.")
            return

        if len(new_password) > 20:
            self.error_label.setText("Пароль не может быть длиннее 20 символов.")
            return

        accounts = load_accounts()
        if accounts:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            accounts[0]["password"] = hashed_password.decode('utf-8')
            save_accounts(accounts)
            self.error_label.setText("Пароль успешно изменен.")
            self.accept()

        else:
            self.error_label.setText("Аккаунт не найден.")

# SkinSettingsDialog удален - скины больше не поддерживаются

def get_saved_skin_is_slim():
    try: 
        settings_path = os.path.join(LAUNCHER_FILES_DIR, 'skin_settings.json')
        if os.path.exists(settings_path):
            with open(settings_path, 'r') as f:
                settings = json.load(f)
                return settings.get('skin_type') == 'slim'
    except Exception:
        pass
    return False

# Функции скинов удалены

def get_pack_format(version_parts):
    if version_parts[0] == 1:
        if version_parts[1] >= 21: return 48
        if version_parts[1] >= 20: return 34
        if version_parts[1] >= 19: return 12
        if version_parts[1] >= 18: return 9
        if version_parts[1] >= 17: return 8
        if version_parts[1] >= 16: return 7
        if version_parts[1] >= 15: return 6
        if version_parts[1] >= 13: return 4
        if version_parts[1] >= 11: return 3
        if version_parts[1] >= 9:  return 2
        if version_parts[1] >= 6:  return 1
        if version_parts[1] >= 5:  return 1
    return 0

def generate_offline_uuid(username, slim=False):
    """Генерирует стабильный оффлайн-UUID типа 3 на основе имени. Для slim используем отдельный namespace,
    чтобы стабильно получать UUID с нужным bit-маском slim/wide на некоторых клиентах."""
    try:
        name = f"OfflinePlayer:{username}" if not slim else f"OfflinePlayerSlim:{username}"
        md5 = hashlib.md5(name.encode('utf-8')).hexdigest()
        # Формируем UUID версии 3
        md5_bytes = bytearray.fromhex(md5)
        md5_bytes[6] = (md5_bytes[6] & 0x0F) | 0x30  # версия 3
        md5_bytes[8] = (md5_bytes[8] & 0x3F) | 0x80  # RFC 4122 variant
        return str(_uuid.UUID(bytes=bytes(md5_bytes)))
    except Exception:
        return str(uuid1())

def get_saved_skin_is_slim():
    try:
        settings_path = os.path.join(LAUNCHER_FILES_DIR, 'skin_settings.json')
        if os.path.exists(settings_path):
            with open(settings_path, 'r') as f:
                settings = json.load(f)
                return settings.get('skin_type') == 'slim'
    except Exception:
        pass
    return False

class LaunchThread(QtCore.QThread):
    launch_setup_signal = QtCore.pyqtSignal(str, str)  # Changed from 3 to 2 arguments
    progress_update_signal = QtCore.pyqtSignal(int, int, str)
    state_update_signal = QtCore.pyqtSignal(bool)
    game_started_signal = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.version_id = ''
        self.username = ''
        self.progress = 0
        self.progress_max = 0
        self.progress_label = ''
        self.running = True

    def launch_setup(self, version_id, username):
        self.version_id = version_id
        self.username = username

    def update_progress_label(self, value):
        self.progress_label = value
        self.progress_update_signal.emit(self.progress, self.progress_max, self.progress_label)

    def update_progress(self, value):
        self.progress = value
        self.progress_update_signal.emit(self.progress, self.progress_max, self.progress_label)

    def update_progress_max(self, value):
        self.progress_max = value
        self.progress_update_signal.emit(self.progress, self.progress_max, self.progress_label)

    def run(self):
        self.running = True
        if is_version_in_mojang_manifest(self.version_id):
            if not download_minecraft_version(self.version_id, minecraft_directory):
                return
        else:
            local_profile = fetch_local_version_data(self.version_id)
            if not local_profile:
                logging.error(f"Локальный профиль версии {self.version_id} не найден")
                return
            base_version = local_profile.get('inheritsFrom')
            if base_version:
                download_minecraft_version(base_version, minecraft_directory)
        launch_minecraft(self.version_id, self.username, minecraft_directory)
        self.game_started_signal.emit()
        self.running = False

"""
Удалены классы DevConsoleWindow/QtLogHandler по требованию пользователя.
"""

class VersionListItem(QtWidgets.QPushButton):
    """Простой элемент списка версий"""
    selected = pyqtSignal(str, str)  # display_text, version_data
    
    def __init__(self, display_text, version_data, item_type="version"):
        super().__init__()
        self.display_text = display_text
        self.version_data = version_data
        self.item_type = item_type
        self.is_selected = False
        
        self.setText(display_text)
        self.setMinimumHeight(25)
        self.setMaximumHeight(25)
        
        self.update_style()
        self.clicked.connect(self.on_clicked)
    
    def update_style(self):
        """Обновляет стиль элемента"""
        if self.is_selected:
            background = "#61afef"
            text_color = "#ffffff"
        else:
            background = "#44475a"
            text_color = "#ffffff"
        
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {background};
                color: {text_color};
                border: none;
                border-radius: 2px;
                padding: 3px 8px;
                font-size: 11px;
                text-align: left;
            }}
            QPushButton:hover {{
                background-color: #61afef;
                color: #ffffff;
            }}
        """)
    
    def set_selected(self, selected):
        """Устанавливает состояние выбора"""
        self.is_selected = selected
        self.update_style()
    
    def on_clicked(self):
        """Обработчик клика"""
        self.selected.emit(self.display_text, self.version_data)


class AnimatedVersionList(QtWidgets.QWidget):
    """Простой кастомный список версий"""
    version_selected = pyqtSignal(str, str)  # display_text, version_data
    
    def __init__(self):
        super().__init__()
        self.selected_item = None
        self.items = []
        
        # Основной layout
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        # Простой скролл список
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.scroll_area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: #44475a;
                border: 1px solid #6272a4;
                border-radius: 4px;
            }
        """)
        
        # Контейнер для элементов списка
        self.list_widget = QtWidgets.QWidget()
        self.list_layout = QtWidgets.QVBoxLayout(self.list_widget)
        self.list_layout.setContentsMargins(2, 2, 2, 2)
        self.list_layout.setSpacing(1)
        
        self.scroll_area.setWidget(self.list_widget)
        layout.addWidget(self.scroll_area)
    
    def add_version(self, display_text, version_data, item_type="version"):
        """Добавляет версию в список"""
        item = VersionListItem(display_text, version_data, item_type)
        item.selected.connect(self.on_item_selected)
        
        self.items.append(item)
        self.list_layout.addWidget(item)
    
    def clear_versions(self):
        """Очищает список версий"""
        for item in self.items:
            item.deleteLater()
        self.items.clear()
        self.selected_item = None
    
    def on_item_selected(self, display_text, version_data):
        """Обработчик выбора элемента"""
        # Убираем выделение с предыдущего элемента
        if self.selected_item:
            self.selected_item.set_selected(False)
        
        # Находим и выделяем новый элемент
        sender = self.sender()
        if isinstance(sender, VersionListItem):
            sender.set_selected(True)
            self.selected_item = sender
        
        # Эмитим сигнал о выборе
        self.version_selected.emit(display_text, version_data)
    
    def get_selected_version(self):
        """Возвращает выбранную версию"""
        if self.selected_item:
            return self.selected_item.display_text, self.selected_item.version_data
        return None, None


class SettingsDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Настройки")
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setFixedSize(400, 300)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")

        self.layout = QtWidgets.QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)

        # Add Launcher icon
        self.launcher_icon_label = QtWidgets.QLabel()
        icon = QIcon(os.path.join(IMAGES_DIR, "Аватарка лаунчера.png"))
        self.launcher_icon_label.setPixmap(icon.pixmap(25, 25))
        self.launcher_icon_label.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        self.layout.addWidget(self.launcher_icon_label)

        self.central_widget = QtWidgets.QWidget()
        self.central_layout = QtWidgets.QVBoxLayout(self.central_widget)
        self.central_layout.setAlignment(QtCore.Qt.AlignCenter)

        # Кастомный анимированный список версий (компактный)
        self.version_list = AnimatedVersionList()
        self.version_list.setMaximumHeight(120)  # Ограничиваем высоту
        self.version_list.setMinimumWidth(150)  # Делаем список шире
        self.version_list.version_selected.connect(self.on_version_selected)
        self.central_layout.addWidget(self.version_list, alignment=QtCore.Qt.AlignCenter)

        self.filter_button = QtWidgets.QPushButton("Фильтр", self)
        self.filter_button.setStyleSheet("""
            QPushButton {
                background-color: #61afef;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 10px;
                min-width: 100px;
                max-width: 100px;
            }
            QPushButton:hover {
                background-color: #508acc;
            }
        """)
        self.central_layout.addWidget(self.filter_button, alignment=QtCore.Qt.AlignCenter)

        self.layout.addStretch()
        self.layout.insertWidget(1, self.central_widget, alignment=QtCore.Qt.AlignCenter)
        self.layout.setStretchFactor(self.launcher_icon_label, 0)
        self.layout.setStretchFactor(self.central_widget, 2)
        self.layout.insertStretch(2)

        self.launch_button = QtWidgets.QPushButton("Запустить")
        self.cancel_button = QtWidgets.QPushButton("Отмена")

        button_style = """
            QPushButton {
                background-color: #61afef;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #508acc;
            }
        """
        self.launch_button.setStyleSheet(button_style)
        self.cancel_button.setStyleSheet(button_style)

        self.launch_button.setMinimumWidth(120)
        self.launch_button.setMinimumHeight(30)
        self.cancel_button.setMinimumWidth(80)
        self.cancel_button.setMinimumHeight(25)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)

        main_bottom_layout = QtWidgets.QVBoxLayout()
        main_bottom_layout.addStretch()
        main_bottom_layout.addWidget(self.launch_button, alignment=QtCore.Qt.AlignCenter)
        main_bottom_layout.addLayout(button_layout)

        self.layout.addLayout(main_bottom_layout)

        self.launch_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        self.filter_button.clicked.connect(self.toggle_version_list)

        self.load_settings()  # Call this method before using self.settings

        self.is_filtering = False
        self.show_snapshots = self.settings.get('show_snapshots', False)
        self.show_fabric = self.settings.get('show_fabric', False)
        self.selected_version_data = None

        self.layout.addStretch()
        self.layout.setStretchFactor(main_bottom_layout, 1)

        self.minecraft_directory = get_minecraft_directory()
        self.update_version_list()
    
    def on_version_selected(self, display_text, version_data):
        """Обработчик выбора версии"""
        self.selected_version_data = version_data
        self.launch_button.setEnabled(True)
        logging.info(f"✅ Выбрана версия: {display_text} (ID: {version_data})")
    
    def get_selected_version_data(self):
        """Возвращает данные выбранной версии"""
        return self.selected_version_data

    def update_version_list(self):
        # Очищаем старый список
        self.version_list.clear_versions()
        
        # Сначала локальные версии (включая уже установленные Fabric)
        for v in sorted(list_local_versions()):
            # Скрываем Fabric-профили, если опция выключена
            if (not self.show_fabric) and (v.startswith('fabric-') or 'fabric-loader-' in v):
                continue
            
            # Форматируем название для отображения, но сохраняем оригинальный ID как данные
            display_name = format_fabric_display_name(v)
            item_type = "fabric" if v.startswith('fabric-') or 'fabric-loader-' in v else "version"
            self.version_list.add_version(display_name, v, item_type)
            
        # Затем официальные версии
        manifest = fetch_mojang_manifest()
        if manifest:
            versions = manifest['versions']
            # Ограничиваем список до N, чтобы UI не тормозил
            MAX_LISTED = 200
            count = 0
            added_versions = set([v for v in list_local_versions()])
            
            for version in versions:
                if (not self.is_filtering or self.is_version_installed(version['id'])) and \
                   (self.show_snapshots or version['type'] != 'snapshot'):
                    # Избегаем дублей
                    if version['id'] not in added_versions:
                        self.version_list.add_version(version['id'], version['id'], "version")
                        added_versions.add(version['id'])
                        
                        # Добавляем пункт установки Fabric только если включено в настройках и фильтр выключен
                        if self.show_fabric and not self.is_filtering:
                            fabric_display = f"{version['id']} (Fabric)"
                            fabric_data = f"install_fabric_{version['id']}"
                            self.version_list.add_version(fabric_display, fabric_data, "fabric_install")
                        count += 1
                        if count >= MAX_LISTED:
                            break

    def toggle_version_list(self):
        self.is_filtering = not self.is_filtering
        if self.is_filtering:
            self.filter_button.setText("Показать все версии")
        else:
            self.filter_button.setText("Фильтр")
        self.update_version_list()

    def is_version_installed(self, version_id):
        version_path = os.path.join(self.minecraft_directory, 'versions', version_id, f'{version_id}.jar')
        if os.path.exists(version_path):
            return True
        # Для производных (Fabric) считаем установленной при наличии profile JSON
        json_path = os.path.join(self.minecraft_directory, 'versions', version_id, f'{version_id}.json')
        return os.path.exists(json_path)


    def load_settings(self):
        self.settings_path = os.path.join(LAUNCHER_FILES_DIR, "launcher_settings.json")
        try:
            with open(self.settings_path, 'r') as f:
                self.settings = json.load(f)
        except:
            self.settings = {'ram': 2, 'show_snapshots': False, 'show_fabric': False}

    def save_settings(self):
        self.settings['ram'] = self.ram_spin.value()
        self.settings['show_snapshots'] = self.snapshots_checkbox.isChecked()
        with open(self.settings_path, 'w') as f:
            json.dump(self.settings, f)
        self.accept()

    def open_console(self):
        QMessageBox.information(self, "Консоль", "Консоль пока не реализована")

# ---- Система уведомлений ----

class NotificationWidget(QtWidgets.QWidget):
    """Виджет уведомлений с плавным исчезновением через 10 секунд"""
    
    def __init__(self, parent=None, message="", duration=10000):
        super().__init__(parent)
        self.duration = duration
        self.setupUi(message)
        self.setupAnimation()
        
    def setupUi(self, message):
        self.setFixedSize(350, 80)
        self.setStyleSheet("""
            QWidget {
                background-color: rgba(44, 47, 51, 230);
                border: 2px solid #61afef;
                border-radius: 8px;
                color: #ffffff;
                font-size: 12px;
            }
        """)
        
        # Layout
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 10)
        
        # Заголовок
        title_label = QtWidgets.QLabel("🎮 Новый запрос в друзья!")
        title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #61afef;")
        layout.addWidget(title_label)
        
        # Сообщение
        message_label = QtWidgets.QLabel(message)
        message_label.setWordWrap(True)
        message_label.setStyleSheet("color: #ffffff; font-size: 12px;")
        layout.addWidget(message_label)
        
        # Кнопка закрытия
        self.close_btn = QtWidgets.QPushButton("✕")
        self.close_btn.setFixedSize(20, 20)
        self.close_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                color: #ffffff;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 0, 0, 100);
                border-radius: 10px;
            }
        """)
        self.close_btn.clicked.connect(self.hide_notification)
        
        # Размещаем кнопку в правом верхнем углу
        self.close_btn.setParent(self)
        self.close_btn.move(self.width() - 25, 5)
        
    def setupAnimation(self):
        # Анимация появления
        self.fade_in_effect = QtWidgets.QGraphicsOpacityEffect()
        self.setGraphicsEffect(self.fade_in_effect)
        
        self.fade_in_animation = QtCore.QPropertyAnimation(self.fade_in_effect, b"opacity")
        self.fade_in_animation.setDuration(500)
        self.fade_in_animation.setStartValue(0)
        self.fade_in_animation.setEndValue(1)
        
        # Анимация исчезновения
        self.fade_out_animation = QtCore.QPropertyAnimation(self.fade_in_effect, b"opacity")
        self.fade_out_animation.setDuration(2000)  # 2 секунды на исчезновение
        self.fade_out_animation.setStartValue(1)
        self.fade_out_animation.setEndValue(0)
        self.fade_out_animation.finished.connect(self.deleteLater)
        
        # Таймер для автоматического скрытия
        self.hide_timer = QtCore.QTimer()
        self.hide_timer.timeout.connect(self.hide_notification)
        self.hide_timer.setSingleShot(True)
        
    def show_notification(self):
        """Показать уведомление с анимацией"""
        self.show()
        self.raise_()
        self.fade_in_animation.start()
        self.hide_timer.start(self.duration)
        
    def hide_notification(self):
        """Скрыть уведомление с плавным исчезновением"""
        self.hide_timer.stop()
        self.fade_out_animation.start()


class FriendNotificationManager(QtCore.QObject):
    """Менеджер уведомлений о запросах в друзья"""
    
    friend_request_received = QtCore.pyqtSignal(str, str)  # sender_name, message
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_widget = parent
        self.check_timer = QtCore.QTimer()
        self.check_timer.timeout.connect(self.check_friend_requests)
        self.last_request_count = 0
        
    def start_checking(self, interval=5000):  # Проверка каждые 5 секунд
        """Запустить периодическую проверку запросов в друзья"""
        self.check_timer.start(interval)
        
    def stop_checking(self):
        """Остановить проверку"""
        self.check_timer.stop()
        
    def check_friend_requests(self):
        """Проверить новые запросы в друзья через API"""
        try:
            # Проверяем, есть ли активный пользователь
            accounts = load_accounts()
            if not accounts or not accounts[0].get('accessToken'):
                return
                
            # Делаем запрос к API
            session = requests.Session()
            headers = get_auth_headers()
            response = session.get(f"{BACKEND_BASE_URL}/api/friends/pending-notifications", headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    pending_count = data.get('pending_count', 0)
                    latest_sender = data.get('latest_sender')
                    
                    # Если количество запросов увеличилось, показываем уведомление
                    if pending_count > self.last_request_count and latest_sender:
                        message = f"Пользователь {latest_sender} хочет добавить вас в друзья!"
                        self.show_notification(latest_sender, message)
                        
                    self.last_request_count = pending_count
            elif response.status_code == 401:
                # Токен недействителен - останавливаем периодические запросы
                self.stop_checking()
                    
        except Exception as e:
            pass  # Тихо игнорируем ошибки проверки друзей
            
    def show_notification(self, sender_name, message):
        """Показать уведомление о новом запросе в друзья"""
        if self.parent_widget:
            notification = NotificationWidget(self.parent_widget, message)
            
            # Позиционируем уведомление в правом верхнем углу
            parent_rect = self.parent_widget.geometry()
            notification.move(
                parent_rect.width() - notification.width() - 20,
                20
            )
            
            notification.show_notification()
            self.friend_request_received.emit(sender_name, message)


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        self.MainWindow = MainWindow
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(720, 480)
        MainWindow.setFixedSize(720, 480)
        MainWindow.setWindowFlags(QtCore.Qt.FramelessWindowHint)

        # Формируем строку CSS с помощью Python
        css_string = f"""
        QMainWindow {{
            background-color: #333333;
            background-image: url('{os.path.join(IMAGES_DIR, 'главная страница.png').replace('\\', '/')}');
            background-repeat: no-repeat;
            background-position: center;
        }}
        """

        # Применяем CSS к главному окну
        MainWindow.setStyleSheet(css_string)

        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        # Добавляем возможность перетаскивания окна
        self.m_flag = False
        self.m_Position = None
        self.set_mouse_events(MainWindow)

        # Удалена логика автозапуска окна консоли разработчика

        # Кнопку быстрого открытия консоли удалили по пожеланию пользователя

        # Кнопка запуска
        # Размер по изображению и овал; позиция в правом нижнем углу с отступом 5px
        play_icon_path = os.path.join(IMAGES_DIR, "Play.png")
        play_pix = QtGui.QPixmap(play_icon_path)
        if not play_pix.isNull():
            button_width = play_pix.width()
            button_height = play_pix.height()
        else:
            button_width = 160
            button_height = 80
        x = 720 - 10 - button_width
        y = 480 - 10 - button_height
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(x, y, button_width, button_height)  # x, y, width, height
        self.pushButton.setStyleSheet("""
            QPushButton {
                background-color:rgba(97, 175, 239, 0);
                color: #ffffff;
                border: none;
                border-radius: 999px;
                padding: 10px 20px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color:rgba(80, 138, 204, 0);
            }
        """)
        icon = QtGui.QIcon(play_pix if not play_pix.isNull() else os.path.join(IMAGES_DIR, "Play.png"))
        
        # Кнопка выхода перенесена в меню профиля
        self.pushButton.setIcon(icon)
        self.pushButton.setIconSize(QtCore.QSize(button_width, button_height))
        self.pushButton.setFixedSize(button_width, button_height)
        self.pushButton.setText("")  # Убираем текст из кнопки запуска

        # Кнопка закрытия
        self.close_button = QtWidgets.QPushButton(self.centralwidget)
        # Сдвигаем кнопку закрытия правее на 5px (отступ теперь ~5px)
        self.close_button.setGeometry(720 - 25 - 5, 3, 25, 25)  # x, y, width, height
        self.close_button.setStyleSheet("""
            QPushButton {
                background-color:rgba(68, 71, 90, 0);
                color: #ffffff;
                border: none;
                border-radius: 4px;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color:rgb(250, 44, 61);
            }
        """)
        icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Close.png"))  # Укажите путь к вашему изображению
        self.close_button.setIcon(icon)
        self.close_button.setIconSize(QtCore.QSize(25, 25))  # Размер иконки
        self.close_button.setFixedSize(25, 25)

        # Кнопка профиля
        self.circular_button = QtWidgets.QPushButton(self.centralwidget)
        # Кнопка профиля: поднять ещё выше на 10px
        self.circular_button.setGeometry(15, 150, 36, 36)  # x, y, width, height
        self.circular_button.setStyleSheet("""
            QPushButton {
                border: none;
                border-radius: 18px;
                background-color: #333333;
            }
            QPushButton:hover {
                background-color: #61afef;
            }
        """)
        icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Аватарка лаунчера.png"))  # Укажите путь к вашему изображению
        self.circular_button.setIcon(icon)
        self.circular_button.setIconSize(QtCore.QSize(22, 22))  # Размер иконки
        self.circular_button.setFixedSize(36, 36)

        # Ник пользователя в главном меню удалён

        # Кнопка сворачивания окна
        self.minimize_button = QtWidgets.QPushButton(self.centralwidget)
        # Размещаем вплотную к кнопке закрытия (без зазора)
        self.minimize_button.setGeometry((720 - 25 - 5) - 25, 3, 25, 25)
        self.minimize_button.setStyleSheet("""
            QPushButton {
                background-color:rgba(105, 105, 105, 0);
                color: #ffffff;
                border: none;
                border-radius: 4px;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color:rgb(0, 247, 255);
            }
        """)
        icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Сurtail.png"))  # Укажите путь к вашему изображению
        self.minimize_button.setIcon(icon)
        self.minimize_button.setIconSize(QtCore.QSize(25, 25))  # Размер иконки
        self.minimize_button.setFixedSize(25, 25)
        self.minimize_button.clicked.connect(MainWindow.showMinimized)  # Подключаем к сворачиванию

        # Круглая кнопка Друзья (для будущего списка друзей) — под кнопкой сворачивания
        self.friends_button = QtWidgets.QPushButton(self.centralwidget)
        # Выравниваем по правому краю относительно minimize и делаем больше (36x36)
        friends_size = 36
        minimize_x = (720 - 25 - 5) - 25
        minimize_y = 3
        minimize_w = 25
        minimize_h = 25
        friends_x = (minimize_x + minimize_w) - friends_size
        friends_y = minimize_y + minimize_h + 5
        self.friends_button.setGeometry(friends_x, friends_y, friends_size, friends_size)
        self.friends_button.setStyleSheet("""
            QPushButton {
                background-color: #2b2b2b;
                color: #ffffff;
                border: none;
                border-radius: 18px;
            }
            QPushButton:hover {
                background-color: #444444;
            }
        """)
        self.friends_button.setText("")
        self.friends_button.setFixedSize(friends_size, friends_size)
        self.friends_button.clicked.connect(self.on_friends_button_clicked)
        # Иконка Friends.png на кнопке
        try:
            friends_icon_path = os.path.join(IMAGES_DIR, "Friends.png")
            if os.path.exists(friends_icon_path):
                friends_icon = QtGui.QIcon(friends_icon_path)
                self.friends_button.setIcon(friends_icon)
                self.friends_button.setIconSize(QtCore.QSize(24, 24))
                self.friends_button.setToolTip("Друзья")
        except Exception:
            pass

        # Кнопка открытия папки Minecraft (изменена)
        folder_button_size = 36
        self.open_folder_button = QtWidgets.QPushButton(self.centralwidget)
        # Кнопку папки опустить ещё на 10px
        self.open_folder_button.setGeometry(15, 300, folder_button_size, folder_button_size)
        self.open_folder_button.setStyleSheet("""
            QPushButton {
                background-color: #61afef;
                color: #ffffff;
                border: none;
                border-radius: 18px;
            }
            QPushButton:hover {
                background-color: #508acc;
            }
        """)
        icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Folder.png"))
        self.open_folder_button.setIcon(icon)
        self.open_folder_button.setIconSize(QtCore.QSize(folder_button_size, folder_button_size))
        self.open_folder_button.setFixedSize(folder_button_size, folder_button_size)
        self.open_folder_button.clicked.connect(self.open_minecraft_folder)

        # Новая кнопка настроек лаунчера
        self.settings_button = QtWidgets.QPushButton(self.centralwidget)
        # Кнопку настроек опустить, сохраняя 5px от папки (папка 300 => 300-36-5=259)
        self.settings_button.setGeometry(15, 259, folder_button_size, folder_button_size)
        self.settings_button.setStyleSheet("""
            QPushButton {
                background-color: #61afef;
                color: #ffffff;
                border: none;
                border-radius: 18px;
            }
            QPushButton:hover {
                background-color: #508acc;
            }
        """)
        icon_settings = QtGui.QIcon(os.path.join(IMAGES_DIR, "Settings.png"))  # Убедитесь, что файл существует
        self.settings_button.setIcon(icon_settings)
        self.settings_button.setIconSize(QtCore.QSize(folder_button_size, folder_button_size))
        self.settings_button.setFixedSize(folder_button_size, folder_button_size)
        self.settings_button.clicked.connect(self.open_settings)

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.pushButton.clicked.connect(self.launch_game)
        self.close_button.clicked.connect(MainWindow.close)
        self.circular_button.clicked.connect(self.on_circular_button_clicked)


        self.launch_threads = []  # Список для хранения потоков запуска
        self.version_id = None

        # Store a reference to the main window
        self.main_window = MainWindow

        # Инициализация атрибута для хранения времени последнего успешного входа
        self.last_login_time = 0

        # Загружаем аккаунты
        accounts = load_accounts()

        # Проверка и отображение диалогового окна входа/регистрации
        if not accounts or not accounts[0].get('accessToken'):
            self.show_login_dialog()
        else:
            # Устанавливаем имя пользователя из аккаунта, если он есть
            if accounts:
                username = accounts[0]["username"]
                self.pushButton.show()
                # Автоматически применяем скин при запуске
                self.apply_auto_skin(username)
            else:
                self.pushButton.hide()

        # Подключаем слот для очистки launch_threads
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        # Применим выбранный аватар
        try:
            self.apply_profile_avatar_icon()
        except Exception:
            pass

        # Панель друзей и чата (скрыта по умолчанию)
        self.create_friends_chat_panel()
        self.friends_panel.setVisible(False)
        
        # Инициализация системы уведомлений о запросах в друзья
        self.notification_manager = FriendNotificationManager(MainWindow)
        self.notification_manager.friend_request_received.connect(self.on_friend_request_received)
        
        # Синхронизируем токен с backend при запуске (асинхронно)
        try:
            import threading
            def sync_token_async():
                result = sync_token_with_backend()
                if result == "reauth_required":
                    # Показываем диалог переавторизации в основном потоке
                    QtCore.QMetaObject.invokeMethod(
                        self, "show_reauth_dialog", 
                        QtCore.Qt.QueuedConnection
                    )
            threading.Thread(target=sync_token_async, daemon=True).start()
        except Exception:
            pass
        
        self.notification_manager.start_checking()

        # --- Добавляем таймер автообновления чата ---
        self.chat_refresh_timer = QtCore.QTimer()
        self.chat_refresh_timer.setInterval(2500)  # 2.5 секунды
        self.chat_refresh_timer.timeout.connect(self._auto_refresh_chat)

    def _auto_refresh_chat(self):
        # Обновлять только если панель друзей открыта и выбран чат
        if hasattr(self, 'friends_panel') and self.friends_panel.isVisible():
            if hasattr(self, 'current_chat_uuid') and self.current_chat_uuid:
                # Не обновлять если диалог добавления друга открыт (чтобы не мешать)
                self.load_chat_history(self.current_chat_uuid)

    @QtCore.pyqtSlot()
    def show_reauth_dialog(self):
        """Показывает диалог переавторизации при устаревшем токене"""
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Warning)
        msg.setWindowTitle("Требуется переавторизация")
        msg.setText("Ваш токен авторизации устарел после перезахода на сайте.\n\nДля использования системы друзей необходимо авторизоваться заново.")
        msg.addButton("Авторизоваться", QtWidgets.QMessageBox.AcceptRole)
        msg.addButton("Пропустить", QtWidgets.QMessageBox.RejectRole)
        
        result = msg.exec_()
        if result == 0:  # Авторизоваться
            clear_saved_accounts()
            # Останавливаем проверку уведомлений перед переавторизацией
            self.notification_manager.stop_checking()
            self.show_login_dialog()

    def logout_account(self):
        """Выход из аккаунта"""
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Question)
        msg.setWindowTitle("Выход из аккаунта")
        msg.setText("Вы уверены, что хотите выйти из аккаунта?\n\nЭто потребует повторной авторизации для запуска игры и использования системы друзей.")
        msg.addButton("Выйти", QtWidgets.QMessageBox.AcceptRole)
        msg.addButton("Отмена", QtWidgets.QMessageBox.RejectRole)
        
        result = msg.exec_()
        if result == 0:  # Выйти
            clear_saved_accounts()
            self.pushButton.hide()
            # Останавливаем проверку уведомлений
            self.notification_manager.stop_checking()
            # Сразу предлагаем войти заново
            self.show_login_dialog()

    def show_login_dialog(self):
        # Полностью без UI: device-flow через сайт
        accs = load_accounts()
        if accs and accs[0].get('accessToken'):
            return
        try:
            r = requests.post(BACKEND_BASE_URL + '/api/device/start', timeout=10)
            d = r.json()
            verify_url = d.get('verification_uri')
            device_code = d.get('device_code')
            if not verify_url or not device_code:
                logging.error('Не удалось начать авторизацию устройства')
                return
            import webbrowser
            webbrowser.open(verify_url)
            for _ in range(200):  # ~10 минут ожидания
                time.sleep(3)
                pr = requests.post(BACKEND_BASE_URL + '/api/device/poll', json={'device_code': device_code}, timeout=10)
                if pr.status_code == 202:
                    continue
                if not pr.ok:
                    logging.error('Ошибка device/poll')
                    return
                pd = pr.json()
                if pd.get('ok'):
                    _save_authenticated_account(pd['username'], pd['accessToken'], pd['clientToken'], pd['uuid'])
                    self.last_login_time = time.time()
                    # Применим скин и покажем кнопки
                    try:
                        self.pushButton.show()
                        self.apply_auto_skin(pd['username'])
                        # Возобновляем проверку уведомлений после успешной авторизации
                        self.notification_manager.start_checking()
                    except Exception:
                        pass
                    return
                else:
                    logging.error(pd.get('message', 'Не удалось авторизоваться'))
                    return
            logging.error('Таймаут подтверждения устройства')
        except Exception as e:
            logging.error(f'Ошибка авторизации через сайт: {e}')
        else:
            self.pushButton.hide()
            # Если вход не удался, то закрываем приложение
        print("Вход не удался. Закрытие приложения.")
        sys.exit(1) # Корректное завершение приложения

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.pushButton.setText(_translate("MainWindow", ""))

    def state_update(self, value):
        # Исправлено: Больше не используем state_update для блокировки кнопки.
        #  Эта функция была причиной блокировки UI.
        print("Запуск!")

    def update_progress(self, progress, maxprogress, label):
        """Обновление прогресса в реальном времени"""
        print(f"[Прогресс] {label}: {progress}/{maxprogress}")

    def game_started(self):
        """Обработчик успешного запуска игры"""
        # Remove the QMessageBox that shows the "Успешный запуск" message
        # QtWidgets.QMessageBox.information(
        #     self.MainWindow,
        #     "Успешный запуск",
        #     "Игра запущена!"
        # )

    def on_circular_button_clicked(self):
        self.profile_dialog = ProfileDialog(self.MainWindow, self)  # Pass both MainWindow and Ui_MainWindow
        self.profile_dialog.exec_()

    def on_friends_button_clicked(self):
        try:
            is_visible = self.friends_panel.isVisible()
            self.friends_panel.setVisible(not is_visible)
            if not is_visible:
                self.friends_panel.raise_()
                self.friends_panel.activateWindow()
                # Запуск таймера автообновления чата
                self.chat_refresh_timer.start()
            else:
                self.chat_refresh_timer.stop()
        except Exception:
            pass

    def apply_profile_avatar_icon(self):
        # Считываем выбранный аватар и применяем к кнопке профиля
        try:
            if os.path.exists(PROFILE_SETTINGS_FILE):
                with open(PROFILE_SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    st = json.load(f)
                path = st.get('profile_avatar_path')
                if path and os.path.exists(path):
                    icon = QtGui.QIcon(path)
                    self.circular_button.setIcon(icon)
                    # Масштабировать под текущий размер кнопки
                    self.circular_button.setIconSize(QtCore.QSize(self.circular_button.width()-4, self.circular_button.height()-4))
        except Exception:
            pass

    def open_settings(self):
        # Оставляем новые настройки лаунчера
        settings_dialog = LauncherSettingsDialog()
        settings_dialog.exec_()

    def launch_game(self):
        """Полная реализация запуска игры с новым интерфейсом"""
        settings_dialog = SettingsDialog()
        if settings_dialog.exec_() == QtWidgets.QDialog.Accepted:
            # Получаем выбранную версию из нового кастомного списка
            selected_data = settings_dialog.get_selected_version_data()
            
            if not selected_data:
                QtWidgets.QMessageBox.warning(
                    self.MainWindow, 
                    "Ошибка", 
                    "Не выбрана версия для запуска!"
                )
                return
            
            # Обрабатываем специальные ID для установки Fabric
            if selected_data.startswith("install_fabric_"):
                base_v = selected_data.replace("install_fabric_", "")
                logging.info(f"🔧 Установка Fabric для версии {base_v}...")
                fabric_id = install_fabric_version(base_v, minecraft_directory)
                if not fabric_id:
                    QtWidgets.QMessageBox.warning(
                        self.MainWindow, 
                        "Ошибка", 
                        "Не удалось установить Fabric для выбранной версии"
                    )
                    return
                self.version_id = fabric_id
                logging.info(f"✅ Fabric установлен: {fabric_id}")
            else:
                # Используем реальный ID версии
                self.version_id = selected_data
                logging.info(f"🎮 Выбрана версия для запуска: {self.version_id}")
            
            # Используем ник из профиля или генерируем случайный
            accounts = load_accounts()
            if accounts:
                username = accounts[0]["username"]
            else:
                username = generate_username()[0]

            # Создаем и настраиваем поток запуска
            launch_thread = LaunchThread()
            launch_thread.launch_setup_signal.connect(launch_thread.launch_setup)
            launch_thread.progress_update_signal.connect(self.update_progress)
            launch_thread.game_started_signal.connect(self.game_started)
            launch_thread.finished.connect(partial(self.remove_thread, launch_thread))

            # Запускаем поток
            self.launch_threads.append(launch_thread)
            launch_thread.start()
            launch_thread.launch_setup_signal.emit(
                self.version_id, 
                username
            )

    def start_game_execution(self):
        """Полная реализация выполнения запуска"""
        if not self.version_id:
            QtWidgets.QMessageBox.warning(
                self.MainWindow,
                "Ошибка запуска",
                "Не выбрана версия!"
            )
            return

        # Запускаем поток с выбранными параметрами
        self.launch_game()

    def remove_thread(self, thread):
        """Корректное удаление потока"""
        if thread in self.launch_threads:
            self.launch_threads.remove(thread)
            thread.quit()
            thread.wait()

    def apply_auto_skin(self, username):
        """Скины удалены"""
        pass

    def open_minecraft_folder(self):
        """Открывает папку Minecraft в проводнике."""
        if not os.path.exists(minecraft_directory):
            QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", "Папка Minecraft не найдена.")
            return

        try:
            if sys.platform == "win32":
                os.startfile(minecraft_directory)
            else:
                webbrowser.open(minecraft_directory)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self.MainWindow, "Ошибка", f"Не удалось открыть папку: {e}")

    def set_mouse_events(self, MainWindow):
        """Устанавливает события мыши для перетаскивания окна."""
        MainWindow.mousePressEvent = self.mousePressEvent
        MainWindow.mouseMoveEvent = self.mouseMoveEvent
        MainWindow.mouseReleaseEvent = self.mouseReleaseEvent

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self.m_flag = True
            self.m_Position = event.globalPos() - self.MainWindow.pos()
            event.accept()

    def mouseMoveEvent(self, event):
        if QtCore.Qt.LeftButton and self.m_flag:
            self.MainWindow.move(event.globalPos() - self.m_Position)
            event.accept()

    def mouseReleaseEvent(self, event):
        self.m_flag = False

    # eventFilter удалён: Ui_MainWindow не QObject

    # -------------------- ДРУЗЬЯ И ЧАТ --------------------
    def create_friends_chat_panel(self):
        # Контейнер панели друзей/чата поверх centralwidget
        self.friends_panel = QtWidgets.QWidget(self.centralwidget)
        self.friends_panel.setGeometry(0, 0, 720, 480)
        self.friends_panel.setStyleSheet("background-color: rgba(20,20,20,230);")

        root_layout = QtWidgets.QHBoxLayout(self.friends_panel)
        root_layout.setContentsMargins(10, 10, 10, 10)
        root_layout.setSpacing(10)

        # Левая часть: окно чата (сверху) + поле ввода (снизу)
        left_container = QtWidgets.QWidget(self.friends_panel)
        left_layout = QtWidgets.QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        # Окно чата: сообщения друга слева, мои справа
        self.chat_view = QtWidgets.QListWidget(left_container)
        self.chat_view.setStyleSheet("""
            QListWidget { background-color:#2b2b2b; color:#ffffff; border:none; }
        """)
        left_layout.addWidget(self.chat_view, 1)

        # Поле ввода + кнопка отправки
        input_row = QtWidgets.QHBoxLayout()
        self.chat_input = QtWidgets.QLineEdit(left_container)
        self.chat_input.setPlaceholderText("Введите сообщение...")
        self.chat_input.setStyleSheet("background-color:#44475a; color:#fff; border:none; border-radius:4px; padding:6px;")
        self.send_button = QtWidgets.QPushButton("Отправить", left_container)
        self.send_button.setStyleSheet("""
            QPushButton { background-color:#61afef; color:#fff; border:none; border-radius:4px; padding:6px 10px; }
            QPushButton:hover { background-color:#508acc; }
        """)
        self.send_button.clicked.connect(self.send_chat_message)
        input_row.addWidget(self.chat_input, 1)
        input_row.addWidget(self.send_button)
        left_layout.addLayout(input_row)

        # Правая часть: список друзей + кнопки
        right_container = QtWidgets.QWidget(self.friends_panel)
        right_container.setFixedWidth(260)
        right_layout = QtWidgets.QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)

        self.friends_list = QtWidgets.QListWidget(right_container)
        self.friends_list.setStyleSheet("""
            QListWidget { background-color:#2b2b2b; color:#ffffff; border:none; }
        """)
        self.friends_list.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        right_layout.addWidget(self.friends_list, 1)

        # Кнопка добавления друга
        self.add_friend_button = QtWidgets.QPushButton("Добавить в друзья", right_container)
        self.add_friend_button.setStyleSheet("""
            QPushButton { background-color:#61afef; color:#fff; border:none; border-radius:4px; padding:6px 10px; }
            QPushButton:hover { background-color:#508acc; }
        """)
        self.add_friend_button.clicked.connect(self.add_friend_dialog)
        right_layout.addWidget(self.add_friend_button)

        # Кнопка назад в главное меню
        self.back_to_main_button = QtWidgets.QPushButton("Назад в меню", right_container)
        self.back_to_main_button.setStyleSheet("""
            QPushButton { background-color:#444444; color:#fff; border:none; border-radius:4px; padding:6px 10px; }
            QPushButton:hover { background-color:#5a5a5a; }
        """)
        self.back_to_main_button.clicked.connect(lambda: self.friends_panel.setVisible(False))
        right_layout.addWidget(self.back_to_main_button)

        # Размещаем контейнеры
        root_layout.addWidget(left_container, 1)
        root_layout.addWidget(right_container, 0)

        # Заполняем список друзей
        self.reload_friends_list()

    def format_chat_item(self, text, is_mine=False):
        # Вспомогательное форматирование выравнивания
        item = QtWidgets.QListWidgetItem(text)
        if is_mine:
            item.setTextAlignment(QtCore.Qt.AlignRight)
        else:
            item.setTextAlignment(QtCore.Qt.AlignLeft)
        return item

    def send_chat_message(self):
        txt = self.chat_input.text().strip()
        if not txt:
            return
            
        # Проверяем, есть ли активный чат
        if not hasattr(self, 'current_chat_uuid') or not self.current_chat_uuid:
            self.chat_view.addItem(self.format_chat_item("Выберите собеседника", is_mine=False))
            return
            
        # Отправляем сообщение через API
        self.send_message_to_api(self.current_chat_uuid, txt)
        
        # Локально добавляем сообщение в чат
        self.chat_view.addItem(self.format_chat_item(txt, is_mine=True))
        self.chat_input.clear()
    
    def send_message_to_api(self, receiver_uuid, message):
        """Отправить сообщение через API"""
        try:
            # Получаем текущий аккаунт
            accounts = load_accounts()
            if not accounts or not accounts[0].get('accessToken'):
                return
                
            # Отправляем сообщение
            session = requests.Session()
            headers = get_auth_headers()
            data = {
                'receiver_uuid': receiver_uuid,
                'message': message
            }
            response = session.post(f"{BACKEND_BASE_URL}/api/chat/send", json=data, headers=headers, timeout=10)
            
            if response.status_code != 200:
                logging.error(f"Ошибка отправки сообщения: {response.status_code}")
                
        except Exception as e:
            logging.error(f"Ошибка отправки сообщения через API: {e}")

    def reload_friends_list(self):
        self.friends_list.clear()
        
        # Загружаем друзей через API
        friends_from_api = self.load_friends_from_api()
        
        # Также добавляем локальных друзей для совместимости
        local_friends = load_friends()
        
        # Объединяем списки, избегая дублей
        all_friends = friends_from_api.copy()
        
        for local_friend in local_friends:
            local_username = local_friend.get("username", "")
            # Проверяем, нет ли уже такого друга из API
            if not any(f['nickname'] == local_username for f in friends_from_api):
                all_friends.append({
                    'nickname': local_username,
                    'uuid': local_friend.get('uuid', ''),
                    'friendship_date': local_friend.get('added_date', ''),
                    'avatar_path': local_friend.get('avatar_path')
                })
        
        # Также загружаем входящие запросы в друзья
        friend_requests = self.load_friend_requests_from_api()
        
        # Отображаем друзей
        for friend in all_friends:
            username = friend.get("nickname", "Безымянный")
            avatar_path = friend.get("avatar_path")
            friend_uuid = friend.get("uuid", "")
            
            # Элемент списка
            item = QtWidgets.QListWidgetItem()
            item.setSizeHint(QtCore.QSize(240, 52))
            widget = QtWidgets.QWidget()
            h = QtWidgets.QHBoxLayout(widget)
            h.setContentsMargins(8, 4, 8, 4)
            h.setSpacing(6)
            
            # Аватар
            avatar_label = QtWidgets.QLabel()
            avatar_label.setFixedSize(40, 40)
            avatar_label.setStyleSheet("background-color:#3a3a3a; border-radius:4px;")
            if avatar_path and os.path.exists(avatar_path):
                pix = QtGui.QPixmap(avatar_path).scaled(40, 40, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
                avatar_label.setPixmap(pix)
            
            # Ник
            name_label = QtWidgets.QLabel(username)
            name_label.setStyleSheet("color:#ffffff;")
            
            # Кнопка чата
            chat_btn = QtWidgets.QPushButton("Чат")
            chat_btn.setStyleSheet("""
                QPushButton { background-color:#61afef; color:#fff; border:none; border-radius:4px; padding:4px 8px; }
                QPushButton:hover { background-color:#508acc; }
            """)
            chat_btn.clicked.connect(lambda _, u=username, uuid=friend_uuid: self.open_chat_with_uuid(u, uuid))
            
            h.addWidget(avatar_label)
            h.addWidget(name_label, 1)
            h.addWidget(chat_btn)
            widget.setLayout(h)
            self.friends_list.addItem(item)
            self.friends_list.setItemWidget(item, widget)
        
        # Отображаем входящие запросы в друзья
        for request in friend_requests:
            sender_name = request.get("sender_nickname", "Безымянный")
            request_id = request.get("id")
            
            # Элемент списка для запроса
            item = QtWidgets.QListWidgetItem()
            item.setSizeHint(QtCore.QSize(240, 60))
            widget = QtWidgets.QWidget()
            widget.setStyleSheet("background-color: rgba(255, 165, 0, 50); border-radius: 4px;")
            h = QtWidgets.QVBoxLayout(widget)
            h.setContentsMargins(8, 4, 8, 4)
            h.setSpacing(2)
            
            # Заголовок запроса
            title_label = QtWidgets.QLabel(f"Запрос от {sender_name}")
            title_label.setStyleSheet("color:#ffaa00; font-weight:bold; font-size:11px;")
            h.addWidget(title_label)
            
            # Кнопки принятия/отклонения
            btn_layout = QtWidgets.QHBoxLayout()
            btn_layout.setSpacing(4)
            
            accept_btn = QtWidgets.QPushButton("Принять")
            accept_btn.setFixedSize(65, 25)
            accept_btn.setStyleSheet("""
                QPushButton { background-color:#61afef; color:#fff; border:none; border-radius:3px; font-size:10px; }
                QPushButton:hover { background-color:#508acc; }
            """)
            accept_btn.clicked.connect(lambda _, rid=request_id: self.accept_friend_request(rid))
            
            decline_btn = QtWidgets.QPushButton("Отклонить")
            decline_btn.setFixedSize(65, 25)
            decline_btn.setStyleSheet("""
                QPushButton { background-color:#e06c75; color:#fff; border:none; border-radius:3px; font-size:10px; }
                QPushButton:hover { background-color:#c86470; }
            """)
            decline_btn.clicked.connect(lambda _, rid=request_id: self.decline_friend_request(rid))
            
            btn_layout.addWidget(accept_btn)
            btn_layout.addWidget(decline_btn)
            btn_layout.addStretch()
            
            h.addLayout(btn_layout)
            widget.setLayout(h)
            self.friends_list.addItem(item)
            self.friends_list.setItemWidget(item, widget)

    def load_friends_from_api(self):
        """Загружает список друзей через API"""
        try:
            # Проверяем авторизацию
            accounts = load_accounts()
            if not accounts or not accounts[0].get('accessToken'):
                return []
                
            session = requests.Session()
            headers = get_auth_headers()
            response = session.get(f"{BACKEND_BASE_URL}/api/friends", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return data.get('friends', [])
            
            return []
        except Exception as e:
            logging.error(f"Ошибка загрузки друзей через API: {e}")
            return []
    
    def load_friend_requests_from_api(self):
        """Загружает входящие запросы в друзья через API"""
        try:
            # Проверяем авторизацию
            accounts = load_accounts()
            if not accounts or not accounts[0].get('accessToken'):
                return []
                
            session = requests.Session()
            headers = get_auth_headers()
            response = session.get(f"{BACKEND_BASE_URL}/api/friends/requests", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return data.get('requests', [])
            
            return []
        except Exception as e:
            logging.error(f"Ошибка загрузки запросов в друзья через API: {e}")
            return []
    
    def accept_friend_request(self, request_id):
        """Принять запрос в друзья"""
        try:
            session = requests.Session()
            headers = get_auth_headers()
            response = session.post(f"{BACKEND_BASE_URL}/api/friends/requests/{request_id}/accept", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    # Обновляем список друзей
                    self.reload_friends_list()
                    QtWidgets.QMessageBox.information(self.MainWindow, "Успех", "Запрос принят!")
                else:
                    QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", data.get('message', 'Неизвестная ошибка'))
            
        except Exception as e:
            logging.error(f"Ошибка принятия запроса в друзья: {e}")
            QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", "Не удалось принять запрос")
    
    def decline_friend_request(self, request_id):
        """Отклонить запрос в друзья"""
        try:
            session = requests.Session()
            headers = get_auth_headers()
            response = session.post(f"{BACKEND_BASE_URL}/api/friends/requests/{request_id}/decline", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    # Обновляем список друзей
                    self.reload_friends_list()
                    QtWidgets.QMessageBox.information(self.MainWindow, "Успех", "Запрос отклонен")
                else:
                    QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", data.get('message', 'Неизвестная ошибка'))
            
        except Exception as e:
            logging.error(f"Ошибка отклонения запроса в друзья: {e}")
            QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", "Не удалось отклонить запрос")
    
    def open_chat_with_uuid(self, username, uuid):
        """Открыть чат с пользователем по UUID"""
        self.current_chat_uuid = uuid
        self.current_chat_username = username
        self.load_chat_history(uuid)
        # Если friends_panel открыт — запустить таймер автообновления
        if hasattr(self, 'friends_panel') and self.friends_panel.isVisible():
            self.chat_refresh_timer.start()
    
    def load_chat_history(self, receiver_uuid):
        """Загружает историю чата с пользователем"""
        try:
            session = requests.Session()
            headers = get_auth_headers()
            response = session.get(f"{BACKEND_BASE_URL}/api/chat/history/{receiver_uuid}?limit=50", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    self.chat_view.clear()
                    messages = data.get('messages', [])
                    chat_with = data.get('chat_with', 'Неизвестный')
                    
                    # Добавляем заголовок чата
                    self.chat_view.addItem(self.format_chat_item(f"Чат с {chat_with}", is_mine=False))
                    
                    # Добавляем сообщения
                    for message in messages:
                        msg_text = message.get('message', '')
                        is_mine = message.get('is_mine', False)
                        timestamp = message.get('timestamp', '')
                        
                        # Форматируем сообщение с временной меткой
                        if timestamp:
                            try:
                                from datetime import datetime
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                time_str = dt.strftime('%H:%M')
                                formatted_msg = f"[{time_str}] {msg_text}"
                            except:
                                formatted_msg = msg_text
                        else:
                            formatted_msg = msg_text
                            
                        self.chat_view.addItem(self.format_chat_item(formatted_msg, is_mine))
                    
                    # Прокручиваем к последнему сообщению
                    self.chat_view.scrollToBottom()
                    
        except Exception as e:
            logging.error(f"Ошибка загрузки истории чата: {e}")
            self.chat_view.clear()
            self.chat_view.addItem(self.format_chat_item(f"Чат с {self.current_chat_username}", is_mine=False))

    def add_friend_dialog(self):
        # Диалог добавления друга по UUID с предпросмотром профиля
        # Временно скрываем панель, чтобы ничто не перекрывало диалог
        was_panel_visible = False
        try:
            if hasattr(self, 'friends_panel') and self.friends_panel.isVisible():
                was_panel_visible = True
                self.friends_panel.setVisible(False)
        except Exception:
            pass

        dlg = QtWidgets.QDialog(self.MainWindow)
        dlg.setWindowFlags(QtCore.Qt.Dialog | QtCore.Qt.FramelessWindowHint)
        dlg.setWindowModality(QtCore.Qt.ApplicationModal)
        dlg.setStyleSheet("background-color:#333333; color:#ffffff;")
        dlg.setFixedSize(360, 260)
        dlg.setModal(True)
        layout = QtWidgets.QVBoxLayout(dlg)

        uuid_input = QtWidgets.QLineEdit()
        uuid_input.setPlaceholderText("UUID игрока")
        uuid_input.setStyleSheet("background-color:#44475a; color:#fff; border:none; border-radius:4px; padding:6px;")

        preview_group = QtWidgets.QGroupBox("Профиль игрока:")
        preview_group.setStyleSheet("QGroupBox { border:1px solid #444444; border-radius:6px; margin-top:8px; } QGroupBox::title { subcontrol-origin: margin; left:8px; padding:0 4px; }")
        preview_layout = QtWidgets.QHBoxLayout(preview_group)
        avatar_preview = QtWidgets.QLabel()
        avatar_preview.setFixedSize(48, 48)
        avatar_preview.setStyleSheet("background-color:#3a3a3a; border-radius:4px;")
        name_preview = QtWidgets.QLabel("-")
        name_preview.setStyleSheet("color:#ffffff; font-weight:600;")
        preview_layout.addWidget(avatar_preview)
        preview_layout.addWidget(name_preview)

        fetch_btn = QtWidgets.QPushButton("Найти по UUID")
        fetch_btn.setStyleSheet("""
            QPushButton { background-color:#61afef; color:#fff; border:none; border-radius:4px; padding:6px 10px; }
            QPushButton:hover { background-color:#508acc; }
        """)

        add_btn = QtWidgets.QPushButton("Добавить")
        add_btn.setEnabled(False)
        add_btn.setStyleSheet("""
            QPushButton { background-color:#61afef; color:#fff; border:none; border-radius:4px; padding:6px 10px; }
            QPushButton:disabled { background-color:#3a6586; }
            QPushButton:hover:!disabled { background-color:#508acc; }
        """)

        cancel_btn = QtWidgets.QPushButton("Отмена")
        cancel_btn.setStyleSheet("""
            QPushButton { background-color:#444444; color:#fff; border:none; border-radius:4px; padding:6px 10px; }
            QPushButton:hover { background-color:#5a5a5a; }
        """)

        # Локальные переменные для результата
        resolved = {"username": None, "uuid": None, "avatar_path": None}

        def do_fetch():
            uid = uuid_input.text().strip()
            if not uid:
                return
            prof = fetch_profile_by_uuid(uid)
            if not prof or not prof.get("username"):
                name_preview.setText("Не найдено")
                avatar_preview.setPixmap(QtGui.QPixmap())
                add_btn.setEnabled(False)
                return
            name_preview.setText(prof["username"])
            # Скачиваем аватар если доступен, иначе используем аватар из лаунчера (если выбран в настройках профиля)
            local_avatar = download_avatar(prof.get("avatar_url"), prof.get("uuid") or uid)
            if not local_avatar:
                # Пытаемся взять аватар из настроек профиля лаунчера
                fallback = None
                try:
                    if os.path.exists(PROFILE_SETTINGS_FILE):
                        with open(PROFILE_SETTINGS_FILE, 'r', encoding='utf-8') as f:
                            ps = json.load(f)
                            fallback = ps.get('profile_avatar_path')
                except Exception:
                    fallback = None
                local_avatar = fallback
            if local_avatar and os.path.exists(local_avatar):
                pix = QtGui.QPixmap(local_avatar).scaled(48, 48, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
                avatar_preview.setPixmap(pix)
            else:
                avatar_preview.setPixmap(QtGui.QPixmap())
            resolved["username"] = prof["username"]
            resolved["uuid"] = prof.get("uuid") or uid
            resolved["avatar_path"] = local_avatar
            add_btn.setEnabled(True)

        def do_add():
            # Если нажали Добавить без поиска — пробуем найти автоматически
            if not resolved["username"] or not resolved["uuid"]:
                do_fetch()
            if not resolved["username"] or not resolved["uuid"]:
                try:
                    QtWidgets.QMessageBox.warning(self.MainWindow, "Добавление", "Сначала укажите UUID и нажмите 'Найти по UUID'.")
                except Exception:
                    pass
                return
            
            # Отправляем запрос в друзья через API
            try:
                # Проверяем авторизацию перед отправкой
                accounts = load_accounts()
                if not accounts or not accounts[0].get('accessToken'):
                    QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", "Необходимо войти в аккаунт для добавления друзей")
                    return
                
                session = requests.Session()
                headers = get_auth_headers()
                if not headers:
                    QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", "Ошибка авторизации. Перезайдите в аккаунт")
                    return
                
                data = {'uuid': resolved["uuid"]}
                response = session.post(f"{BACKEND_BASE_URL}/api/friends/request", json=data, headers=headers, timeout=10)
                
                # Если 401 ошибка, пробуем синхронизировать токен и повторить
                if response.status_code == 401:
                    sync_result = sync_token_with_backend()
                    if sync_result == True:
                        # Повторяем запрос с обновленными данными
                        headers = get_auth_headers()
                        response = session.post(f"{BACKEND_BASE_URL}/api/friends/request", json=data, headers=headers, timeout=10)
                    elif sync_result == "reauth_required":
                        # Токен устарел, нужна переавторизация
                        msg = QtWidgets.QMessageBox()
                        msg.setIcon(QtWidgets.QMessageBox.Warning)
                        msg.setWindowTitle("Требуется переавторизация")
                        msg.setText("Ваш токен авторизации устарел.\n\nДля добавления друзей необходимо авторизоваться заново.")
                        msg.addButton("Авторизоваться", QtWidgets.QMessageBox.AcceptRole)
                        msg.addButton("Отмена", QtWidgets.QMessageBox.RejectRole)
                        
                        auth_result = msg.exec_()
                        if auth_result == 0:  # Авторизоваться
                            clear_saved_accounts()
                            # Останавливаем проверку уведомлений перед переавторизацией
                            self.notification_manager.stop_checking()
                            self.show_login_dialog()
                            # После авторизации пользователь может попробовать добавить друга снова
                        return
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('ok'):
                        QtWidgets.QMessageBox.information(self.MainWindow, "Успех", result.get('message', 'Запрос отправлен!'))
                        # Также добавляем локально для совместимости
                        friends = load_friends()
                        # Не добавляем дубль по UUID
                        if not any(f.get("uuid") == resolved["uuid"] for f in friends):
                            friends.append({
                                "username": resolved["username"],
                                "uuid": resolved["uuid"],
                                "avatar_path": resolved["avatar_path"]
                            })
                            save_friends(friends)
                        self.reload_friends_list()
                        dlg.accept()
                    else:
                        QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", result.get('message', 'Неизвестная ошибка'))
                elif response.status_code == 401:
                    msg = QtWidgets.QMessageBox()
                    msg.setIcon(QtWidgets.QMessageBox.Warning)
                    msg.setWindowTitle("Ошибка авторизации")
                    msg.setText("Токен авторизации недействителен.\n\nДля решения проблемы:\n1. Откройте сайт AsetWorld\n2. Выйдите из аккаунта (если необходимо)\n3. Войдите заново\n4. В лаунчере нажмите 'Войти' и авторизуйтесь")
                    msg.addButton("Открыть сайт", QtWidgets.QMessageBox.AcceptRole)
                    msg.addButton("Закрыть", QtWidgets.QMessageBox.RejectRole)
                    
                    result = msg.exec_()
                    if result == 0:  # Открыть сайт
                        import webbrowser
                        webbrowser.open("http://89.250.150.135:5500")
                else:
                    QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", f"Ошибка сервера: {response.status_code}")
                    
            except Exception as e:
                logging.error(f"Ошибка отправки запроса в друзья: {e}")
                QtWidgets.QMessageBox.warning(self.MainWindow, "Ошибка", "Не удалось отправить запрос в друзья. Проверьте подключение к интернету.")

        fetch_btn.clicked.connect(do_fetch)
        add_btn.clicked.connect(do_add)
        cancel_btn.clicked.connect(dlg.reject)

        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addWidget(add_btn)
        btn_row.addWidget(cancel_btn)

        layout.addWidget(uuid_input)
        layout.addWidget(fetch_btn)
        layout.addWidget(preview_group)
        layout.addLayout(btn_row)

        # Центрируем диалог относительно главного окна
        try:
            geo = dlg.frameGeometry()
            geo.moveCenter(self.MainWindow.frameGeometry().center())
            dlg.move(geo.topLeft())
        except Exception:
            pass
        
        dlg.exec_()

        # Возвращаем панель в исходное состояние
        try:
            if was_panel_visible:
                self.friends_panel.setVisible(True)
                self.friends_panel.raise_()
                self.friends_panel.activateWindow()
        except Exception:
            pass

    def open_chat_with(self, username):
        # Простая заглушка — заголовок и очистка окна чата
        self.chat_view.clear()
        self.chat_view.addItem(self.format_chat_item(f"Открыт чат с {username}", is_mine=False))
    
    def on_friend_request_received(self, sender_name, message):
        """Обработчик получения нового запроса в друзья"""
        logging.info(f"Получен новый запрос в друзья от {sender_name}: {message}")
        # Можно добавить дополнительную логику, например звуковой сигнал
        # или обновление счетчика непрочитанных запросов

    def show_chat_notification(self, sender, message):
        # Показать уведомление в правом нижнем углу
        notification = NotificationWidget(self.MainWindow, message, duration=7000)
        # Кастомизируем заголовок под чат
        layout = notification.layout()
        if layout and layout.count() > 0:
            title_label = layout.itemAt(0).widget()
            if isinstance(title_label, QtWidgets.QLabel):
                title_label.setText(f'💬 Новое сообщение от {sender}')
        # Позиционируем в правом нижнем углу
        parent_rect = self.MainWindow.geometry()
        x = parent_rect.width() - notification.width() - 20
        y = parent_rect.height() - notification.height() - 20
        notification.move(x, y)
        notification.show_notification()

class CustomProgressBar(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.progress = 0
        self.message = "Загрузка..."

    def setProgress(self, value):
        self.progress = value
        self.update()

    def setMessage(self, message):
        self.message = message
        self.update()

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        rect = self.rect()

        # Draw border
        pen = QtGui.QPen(QtGui.QColor("#333333"))  # Цвет границы совпадает с фоном окна
        pen.setWidth(2)  # Толщина границы
        painter.setPen(pen)
        painter.drawRect(rect.adjusted(0, 0, -1, -1))  # Рисуем границу

        # Draw background
        painter.setBrush(QtGui.QColor("#333333"))  # Цвет фона совпадает с фоном окна
        painter.drawRect(rect.adjusted(1, 1, -2, -2))  # Уменьшаем размер для учета границы

        # Draw progress
        progress_width = int((rect.width() - 2) * (self.progress / 100))  # Учитываем границу
        painter.setBrush(QtGui.QColor("#61afef"))  # Голубой цвет заполнения
        painter.drawRect(1, 1, progress_width, rect.height() - 2)  # Учитываем границу

        # Draw text
        painter.setPen(QtGui.QColor("#ffffff"))  # Цвет текста
        painter.drawText(rect, QtCore.Qt.AlignCenter, self.message)


class SplashScreen(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Splash Screen")
        self.setFixedSize(300, 300)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")

        layout = QtWidgets.QVBoxLayout(self)

        # Контейнер для лого и текста
        top_layout = QtWidgets.QHBoxLayout()
        top_layout.setContentsMargins(10, 10, 10, 0)  # Отступы для верхнего контейнера

        # Иконка лаунчера
        self.icon_label = QtWidgets.QLabel(self)
        icon = QIcon(os.path.join(IMAGES_DIR, "Аватарка лаунчера.png"))  # Укажите путь к вашей иконке
        self.icon_label.setPixmap(icon.pixmap(25, 25))  # Размер иконки
        self.icon_label.setFixedSize(25, 25)
        top_layout.addWidget(self.icon_label)

        # Текст AsetLauncher
        self.title_label = QtWidgets.QLabel("AsetLauncher")
        self.title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        self.title_label.setContentsMargins(2, 0, 0, 0)  # Отступ слева 2 пикселя
        top_layout.addWidget(self.title_label)

        layout.addLayout(top_layout)

        # Добавляем растяжку, чтобы прогресс-бар был точно по центру
        layout.addStretch(1)

        # Кастомный прогресс-бар
        self.custom_progress_bar = CustomProgressBar(self)
        self.custom_progress_bar.setFixedSize(280, 30)  # Размер прогресс-бара
        layout.addWidget(self.custom_progress_bar, alignment=QtCore.Qt.AlignCenter)

        # Добавляем растяжку, чтобы прогресс-бар был точно по центру
        layout.addStretch(1)

        # Добавляем версию лаунчера
        self.version_label = QtWidgets.QLabel("Версия 1.2")
        self.version_label.setStyleSheet("font-size: 10px; color: #888888;")
        self.version_label.setAlignment(QtCore.Qt.AlignLeft)
        
        # Добавляем версию лаунчера в самый низ
        layout.addWidget(self.version_label)

        # Таймер для обновления прогресс-бара
        self.progress_timer = QtCore.QTimer(self)
        self.progress_timer.timeout.connect(self.update_progress)
        self.progress_timer.start(50)  # Обновление каждые 50 мс

        # Таймер для обновления сообщений
        self.message_timer = QtCore.QTimer(self)
        self.message_timer.timeout.connect(self.update_message)
        self.message_timer.start(3000)  # Обновление каждые 3 секунды

        self.progress = 0
        self.messages = [
            "Проверяем ваше настроение",
            "Передаём ауру качественной игры",
            "Загрузка...",
            "Очистка кеша..."
        ]
        self.message_index = 0

    def update_progress(self):
        self.progress += 1
        self.custom_progress_bar.setProgress(self.progress)
        if self.progress >= 100:
            self.progress_timer.stop()
            self.message_timer.stop()
            self.accept()  # Закрыть экран загрузки

    def update_message(self):
        self.message_index = (self.message_index + 1) % len(self.messages)
        self.custom_progress_bar.setMessage(self.messages[self.message_index])

# Функция для загрузки манифеста Mojang
def fetch_mojang_manifest():
    global _MOJANG_MANIFEST_CACHE
    if _MOJANG_MANIFEST_CACHE is not None:
        return _MOJANG_MANIFEST_CACHE
    url = "https://launchermeta.mojang.com/mc/game/version_manifest.json"
    try:
        response = requests.get(url, timeout=DEFAULT_HTTP_TIMEOUT)
        if response.status_code == 200:
            _MOJANG_MANIFEST_CACHE = response.json()
            return _MOJANG_MANIFEST_CACHE
    except Exception as e:
        logging.error(f"Ошибка получения манифеста Mojang: {e}")
    print("Не удалось получить манифест Mojang.")
    return None

# Вспомогательные функции для пользовательских версий (например, Fabric)
def _get_local_version_json_path(version_id):
    version_dir = os.path.join(minecraft_directory, 'versions', version_id)
    return os.path.join(version_dir, f'{version_id}.json')

def is_version_in_mojang_manifest(version_id):
    manifest = fetch_mojang_manifest()
    if not manifest:
        return False
    return any(v.get('id') == version_id for v in manifest.get('versions', []))

def fetch_local_version_data(version_id):
    try:
        with open(_get_local_version_json_path(version_id), 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        logging.error(f"Ошибка чтения локального version.json для {version_id}: {e}")
        return None

def format_fabric_display_name(version_id):
    """Форматирует название Fabric версии для отображения в UI"""
    if version_id.startswith('fabric-loader-') or 'fabric-loader-' in version_id:
        # Извлекаем версию Minecraft из fabric-loader-0.15.11-1.20.1
        parts = version_id.split('-')
        if len(parts) >= 3:
            # Находим часть, которая выглядит как версия Minecraft (содержит точки)
            for part in reversed(parts):
                if '.' in part and not part.startswith('0.'):  # Исключаем версии загрузчика вида 0.x.x
                    return f"Fabric {part}"
        
        # Fallback: если не удалось извлечь версию
        return version_id.replace('fabric-loader-', 'Fabric ')
    return version_id

def list_local_versions():
    versions_root = os.path.join(minecraft_directory, 'versions')
    results = []
    try:
        if not os.path.isdir(versions_root):
            return results
        for entry in os.listdir(versions_root):
            version_dir = os.path.join(versions_root, entry)
            if os.path.isdir(version_dir):
                json_path = os.path.join(version_dir, f"{entry}.json")
                if os.path.isfile(json_path):
                    results.append(entry)
    except Exception as e:
        logging.error(f"Ошибка при сборе локальных версий: {e}")
    return results

# Парсинг числовой версии Minecraft из строки (например, "1.20.1" из "fabric-loader-0.17.2-1.20.1")
def parse_minecraft_version_parts(version_str):
    try:
        m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str)
        if not m:
            return None
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3)) if m.group(3) else 0
        return [major, minor, patch]
    except Exception:
        return None

def resolve_inherits_from(version_id):
    local = fetch_local_version_data(version_id)
    if local and 'inheritsFrom' in local:
        return local['inheritsFrom']
    return None

def is_fabric_supported(vanilla_version_id):
    try:
        resp = requests.get(f"https://meta.fabricmc.net/v2/versions/loader/{vanilla_version_id}", timeout=DEFAULT_HTTP_TIMEOUT)
        if resp.status_code != 200:
            return False
        data = resp.json()
        return isinstance(data, list) and len(data) > 0
    except Exception:
        return False

def install_fabric_version(vanilla_version_id, minecraft_directory, loader_version=None, installer_version=None):
    """Устанавливает профиль Fabric для указанной версии Minecraft и возвращает его id."""
    try:
        # Убедиться, что базовая ванильная версия установлена
        download_minecraft_version(vanilla_version_id, minecraft_directory)

        base_url = "https://meta.fabricmc.net/v2/versions"
        # Получаем последнюю связку: loader берём из loader/<game>, installer из /installer
        if not loader_version:
            resp = requests.get(f"{base_url}/loader/{vanilla_version_id}", timeout=DEFAULT_HTTP_TIMEOUT)
            resp.raise_for_status()
            combos = resp.json()
            if not combos:
                logging.error(f"Fabric не поддерживает версию {vanilla_version_id}")
                return None
            # Ищем стабильный loader, иначе первый
            stable = next((c for c in combos if c.get('loader', {}).get('stable')), None)
            chosen = stable or combos[0]
            loader_version = chosen['loader']['version']
        if not installer_version:
            resp_inst = requests.get(f"{base_url}/installer", timeout=DEFAULT_HTTP_TIMEOUT)
            resp_inst.raise_for_status()
            installers = resp_inst.json()
            if not installers:
                logging.error("Список версий Fabric installer пуст")
                return None
            stable_inst = next((i for i in installers if i.get('stable')), None)
            installer_version = (stable_inst or installers[0])['version']

        # Получаем готовый профиль JSON, совместимый с лаунчером (installer не требуется)
        profile_url = f"{base_url}/loader/{vanilla_version_id}/{loader_version}/profile/json"
        profile_resp = requests.get(profile_url, timeout=DEFAULT_HTTP_TIMEOUT)
        profile_resp.raise_for_status()
        profile = profile_resp.json()

        fabric_version_id = profile.get('id') or f"fabric-loader-{loader_version}-{vanilla_version_id}"

        # Создаем директорию версии и сохраняем профиль
        version_dir = os.path.join(minecraft_directory, 'versions', fabric_version_id)
        os.makedirs(version_dir, exist_ok=True)
        with open(os.path.join(version_dir, f"{fabric_version_id}.json"), 'w', encoding='utf-8') as f:
            json.dump(profile, f)

        logging.info(f"Fabric профиль установлен: {fabric_version_id}")
        return fabric_version_id
    except Exception as e:
        logging.error(f"Не удалось установить Fabric для {vanilla_version_id}: {e}")
        return None

# Функция для загрузки версии Minecraft
def download_minecraft_version(version_id, minecraft_directory):
    manifest = fetch_mojang_manifest()
    if not manifest:
        return False

    version_info = next((v for v in manifest['versions'] if v['id'] == version_id), None)
    if not version_info:
        print(f"Версия {version_id} не найдена в манифесте.")
        return False

    version_url = version_info['url']
    version_data = requests.get(version_url, timeout=DEFAULT_HTTP_TIMEOUT).json()

    # Проверяем существование и хеш клиентского jar
    client_url = version_data['downloads']['client']['url']
    client_path = os.path.join(minecraft_directory, 'versions', version_id, f'{version_id}.jar')
    
    if os.path.exists(client_path):
        logging.info(f"✅ Minecraft {version_id} уже загружен, пропускаем.")
        return True

    # Используем быструю функцию загрузки
    logging.info(f"🎮 Загрузка Minecraft {version_id}...")
    if download_file_fast(client_url, client_path, f"Minecraft {version_id}"):
        logging.info(f"✅ Minecraft {version_id} успешно загружен.")
    return True

def download_file_fast(url, path, description="файл"):
    """Быстрая загрузка файла с логированием и обработкой ошибок"""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        logging.info(f"🔄 Загрузка {description}: {os.path.basename(path)}")
        
        with requests.get(url, stream=True, timeout=30) as response:
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            
            with open(path, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=16384):  # Увеличенный размер чанка
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
        logging.info(f"✅ Успешно загружен {description}: {os.path.basename(path)} ({downloaded} байт)")
        return True
    except Exception as e:
        logging.error(f"❌ Ошибка загрузки {description} {url}: {str(e)}")
        return False

def download_multiple_files(downloads, max_workers=4):
    """Многопоточная загрузка файлов"""
    logging.info(f"🚀 Начинаем многопоточную загрузку {len(downloads)} файлов (потоков: {max_workers})")
    
    def download_task(download_info):
        url, path, description = download_info
        if not os.path.exists(path):
            return download_file_fast(url, path, description)
        else:
            logging.info(f"⏭️  {description} уже существует: {os.path.basename(path)}")
            return True
    
    successful = 0
    failed = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_download = {executor.submit(download_task, download): download for download in downloads}
        
        for future in concurrent.futures.as_completed(future_to_download):
            download = future_to_download[future]
            try:
                result = future.result()
                if result:
                    successful += 1
                else:
                    failed.append(download)
            except Exception as e:
                logging.error(f"❌ Исключение при загрузке {download[0]}: {str(e)}")
                failed.append(download)
    
    logging.info(f"📊 Результат загрузки: {successful} успешно, {len(failed)} неудач")
    return successful, failed

def extract_natives(native_path, natives_dir):
    """Извлекает нативные библиотеки из JAR файла в папку natives"""
    try:
        with zipfile.ZipFile(native_path, 'r') as zip_ref:
            for file in zip_ref.namelist():
                if file.endswith('.dll') or file.endswith('.so') or file.endswith('.dylib'):
                    zip_ref.extract(file, natives_dir)
                    logging.info(f"Извлечена нативная библиотека: {file}")
    except Exception as e:
        logging.error(f"Ошибка при распаковке нативных библиотек из {native_path}: {str(e)}")

def download_libraries(version_data, minecraft_directory):
    """Загружает все необходимые библиотеки для Minecraft в папку версии с многопоточностью"""
    version_id = version_data['id']
    version_dir = os.path.join(minecraft_directory, 'versions', version_id)
    libraries_dir = os.path.join(version_dir, 'libraries')
    natives_dir = os.path.join(version_dir, 'natives')
    
    # Создаем необходимые директории
    os.makedirs(libraries_dir, exist_ok=True)
    os.makedirs(natives_dir, exist_ok=True)
    
    libraries = version_data.get('libraries', [])
    total_libs = len(libraries)
    
    logging.info(f"📚 Начинаем загрузку библиотек для версии {version_id} (всего {total_libs})...")
    
    # Очищаем папку natives перед новой установкой
    if os.path.exists(natives_dir):
        for file in os.listdir(natives_dir):
            os.remove(os.path.join(natives_dir, file))
    
    # Собираем список файлов для загрузки
    downloads = []
    natives_to_extract = []
    
    for library in libraries:
        name = library.get('name', 'Неизвестная библиотека')
        logging.debug(f"📦 Обработка библиотеки: {name}")
        
        # Проверяем правила для библиотеки (используем общую функцию)
        rules_result = _should_include_for_windows(library.get('rules'))
        if not rules_result:
            logging.debug(f"⏭️  Пропуск библиотеки {name} (не требуется для Windows)")
            continue

        downloads_info = library.get('downloads', {})
        
        # Загружаем основной артефакт
        artifact = downloads_info.get('artifact')
        if artifact:
            url = artifact['url']
            # Для Fabric используем полный путь из artifact.path
            if 'path' in artifact:
                path = os.path.join(libraries_dir, artifact['path'])
            else:
                path = os.path.join(libraries_dir, os.path.basename(artifact['url']))
            
            downloads.append((url, path, f"библиотека {os.path.basename(path)}"))
        else:
            # Fallback для старых версий (например, Fabric) - строим URL по имени
            logging.debug(f"📦 Библиотека {name}: нет artifact в downloads, используем fallback")
            try:
                # Парсим имя библиотеки в формате group:artifact:version
                name_parts = name.split(':')
                if len(name_parts) == 3:
                    group, artifact_name, version = name_parts
                    group_path = group.replace('.', '/')
                    
                    # Определяем базовый URL для библиотеки
                    base_url = library.get('url', 'https://libraries.minecraft.net/')
                    if 'fabricmc.net' in base_url:
                        # Для Fabric используем их Maven репозиторий
                        url = f"{base_url}{group_path}/{artifact_name}/{version}/{artifact_name}-{version}.jar"
                    else:
                        # Стандартный URL для библиотек Minecraft
                        url = f"https://libraries.minecraft.net/{group_path}/{artifact_name}/{version}/{artifact_name}-{version}.jar"
                    
                    path = os.path.join(libraries_dir, f"{artifact_name}-{version}.jar")
                    downloads.append((url, path, f"библиотека fallback {artifact_name}-{version}.jar"))
                else:
                    logging.warning(f"❌ Не удалось распарсить имя библиотеки: {name}")
            except Exception as e:
                logging.error(f"❌ Ошибка при обработке библиотеки {name} (fallback): {str(e)}")
                continue
        
        # Обрабатываем нативные библиотеки
        classifiers = downloads_info.get('classifiers', {})
        if classifiers:
            # Определяем правильную версию нативной библиотеки для Windows
            native_keys = ['natives-windows', 'natives-windows-64']
            for native_key in native_keys:
                if native_key in classifiers:
                    native = classifiers[native_key]
                    # Для Fabric используем полный путь
                    if 'path' in native:
                        native_path = os.path.join(libraries_dir, native['path'])
                    else:
                        native_path = os.path.join(libraries_dir, os.path.basename(native['url']))
                    
                    downloads.append((native['url'], native_path, f"нативная библиотека {os.path.basename(native_path)}"))
                    natives_to_extract.append(native_path)
        
        # Обработка старых версий LWJGL (для версий до 1.19)
        if 'natives' in library:
            try:
                natives = library['natives']
                if 'windows' in natives:
                    native_suffix = natives['windows'].replace('${arch}', 'x64')
                    name_parts = library['name'].split(':')
                    if len(name_parts) == 3:
                        group, artifact, version = name_parts
                        group_path = group.replace('.', '/')
                        native_name = f"{artifact}-{version}-{native_suffix}.jar"
                        url = f"https://libraries.minecraft.net/{group_path}/{artifact}/{version}/{native_name}"
                        native_path = os.path.join(libraries_dir, native_name)
                        
                        downloads.append((url, native_path, f"старая нативная библиотека {native_name}"))
                        natives_to_extract.append(native_path)
            except Exception as e:
                logging.error(f"❌ Ошибка при обработке старой нативной библиотеки: {str(e)}")

    # Выполняем многопоточную загрузку всех файлов
    if downloads:
        successful, failed = download_multiple_files(downloads, max_workers=6)
        
        # Извлекаем нативные библиотеки после загрузки
        logging.info(f"🔧 Извлечение нативных библиотек...")
        for native_path in natives_to_extract:
            if os.path.exists(native_path):
                extract_natives(native_path, natives_dir)
        
        logging.info(f"📚 Загрузка библиотек завершена. Успешно: {successful}, неудач: {len(failed)}")
        return successful > 0
    else:
        logging.info(f"📚 Все библиотеки уже загружены")
        return True

def download_assets(version_data, minecraft_directory):
    """Загружает ассеты игры с проверкой существующих файлов"""
    # Если это производная версия (например, Fabric), берем ассеты из базовой ванильной версии
    if 'assetIndex' not in version_data:
        inherits = version_data.get('inheritsFrom')
        if inherits:
            logging.info(f"Версия наследуется от {inherits}, загружаем ассеты оттуда")
            base_data = fetch_version_data(inherits)
            if not base_data or 'assetIndex' not in base_data:
                logging.error("Информация об ассетах не найдена в базовой версии")
                return False
            version_data = base_data
        else:
            logging.error("Информация об ассетах не найдена")
            return False

    asset_index = version_data['assetIndex']
    index_url = asset_index['url']
    
    assets_dir = os.path.join(minecraft_directory, 'assets')
    indexes_dir = os.path.join(assets_dir, 'indexes')
    objects_dir = os.path.join(assets_dir, 'objects')
    
    os.makedirs(indexes_dir, exist_ok=True)
    os.makedirs(objects_dir, exist_ok=True)

    # Проверяем существование индекса
    index_path = os.path.join(indexes_dir, f"{asset_index['id']}.json")
    if not os.path.exists(index_path):
        with requests.get(index_url, timeout=DEFAULT_HTTP_TIMEOUT) as r:
            with open(index_path, 'wb') as f:
                f.write(r.content)

    # Читаем индекс
    with open(index_path, 'r') as f:
        index_data = json.load(f)

    total_assets = len(index_data['objects'])
    
    logging.info(f"🎨 Обработка ассетов (всего {total_assets})...")
    
    # Собираем список файлов для загрузки
    downloads = []
    existing_count = 0
    
    for obj_path, obj_data in index_data['objects'].items():
        hash_value = obj_data['hash']
        hash_path = os.path.join(objects_dir, hash_value[:2], hash_value)
        
        if os.path.exists(hash_path):
            existing_count += 1
            continue

        url = f"https://resources.download.minecraft.net/{hash_value[:2]}/{hash_value}"
        downloads.append((url, hash_path, f"ассет {hash_value[:8]}..."))
    
    logging.info(f"🎨 Найдено {existing_count} существующих ассетов, нужно загрузить {len(downloads)}")
    
    # Выполняем многопоточную загрузку ассетов
    if downloads:
        successful, failed = download_multiple_files(downloads, max_workers=8)
        logging.info(f"🎨 Загрузка ассетов завершена. Успешно: {successful}, неудач: {len(failed)}")
        return successful > 0
    else:
        logging.info(f"🎨 Все ассеты уже загружены")
    return True

# Построение аргументов запуска с учетом modern-формата "arguments"
def _should_include_for_windows(rules):
    if not rules:
        return True
    allowed = False
    for rule in rules:
        action = rule.get('action')
        os_rule = rule.get('os', {})
        os_name = os_rule.get('name')
        if action == 'allow':
            if not os_name or os_name == 'windows':
                allowed = True
        elif action == 'disallow':
            if os_name == 'windows':
                return False
    return allowed

def _expand_placeholders(value, ctx):
    if not isinstance(value, str):
        return value
    for k, v in ctx.items():
        value = value.replace('${' + k + '}', str(v))
    return value

def _resolve_argument_items(items, ctx):
    result = []
    for item in items or []:
        if isinstance(item, str):
            result.append(_expand_placeholders(item, ctx))
        elif isinstance(item, dict):
            if _should_include_for_windows(item.get('rules')):
                val = item.get('value')
                if isinstance(val, list):
                    result.extend([_expand_placeholders(v, ctx) for v in val])
                elif isinstance(val, str):
                    result.append(_expand_placeholders(val, ctx))
    return result

# Обновление функции для запуска Minecraft
# Теперь включает все необходимые библиотеки в classpath
def launch_minecraft(version_id, username, minecraft_directory):
    add_hosts_redirects()
    try:
        # Загрузка настроек
        try:
            # Используем путь в LAUNCHER_FILES_DIR вместо текущей директории
            settings_path = os.path.join(LAUNCHER_FILES_DIR, "launcher_settings.json") 
            with open(settings_path, "r") as f:
                settings = json.load(f)
                ram = settings.get('ram', 2)
                logging.info(f"Загружено значение ОЗУ: {ram} ГБ")  # Логирование загруженного значения ОЗУ
        except Exception as e:
            ram = 2
            logging.warning(f"Не удалось загрузить настройки: {str(e)}, используется значение ОЗУ по умолчанию: 2 ГБ")

        # Скины удалены
        logging.info("Начинаем запуск Minecraft...")
        version_data = fetch_version_data(version_id)
        if not version_data:
            logging.error(f"Не удалось получить данные версии для {version_id}")
            return

        version_dir = os.path.join(minecraft_directory, 'versions', version_id)
        libraries_dir = os.path.join(version_dir, 'libraries')
        natives_dir = os.path.join(version_dir, 'natives')

        # Загрузка библиотек
        logging.info("Загрузка необходимых библиотек...")
        if not download_libraries(version_data, minecraft_directory):
            logging.error("Не удалось загрузить необходимые библиотеки")
            return
        logging.info("Библиотеки успешно загружены")
        
        # Загрузка ассетов
        logging.info("Загрузка игровых ресурсов...")
        if not download_assets(version_data, minecraft_directory):
            logging.error("Не удалось загрузить игровые ресурсы")
            return
        logging.info("Игровые ресурсы успешно загружены")

        # Проверка наличия основного JAR файла
        jar_path = os.path.join(version_dir, f'{version_id}.jar')
        if not os.path.exists(jar_path):
            # Если версия наследуется (Fabric), используем jar базовой ванильной версии
            inherits = version_data.get('inheritsFrom')
            if inherits:
                base_jar = os.path.join(minecraft_directory, 'versions', inherits, f'{inherits}.jar')
                if not os.path.exists(base_jar):
                    # Пытаемся скачать базовую версию
                    download_minecraft_version(inherits, minecraft_directory)
                if os.path.exists(base_jar):
                    jar_path = base_jar
                else:
                    logging.error(f"Не найден основной файл игры: {version_id}.jar и базовый {inherits}.jar")
                    return
            else:
                logging.error(f"Не найден основной файл игры: {version_id}.jar")
                return

        logging.info("Подготовка путей к библиотекам...")
        classpath = [jar_path]
        
        # Добавляем библиотеки из версионной папки (Fabric)
        for file in os.listdir(libraries_dir):
            if file.endswith('.jar'):
                classpath.append(os.path.join(libraries_dir, file))
        
        # Для Fabric также добавляем библиотеки из базовой ванильной версии
        inherits = version_data.get('inheritsFrom')
        if inherits:
            base_libraries_dir = os.path.join(minecraft_directory, 'versions', inherits, 'libraries')
            if os.path.exists(base_libraries_dir):
                logging.info(f"Добавляем библиотеки из базовой версии {inherits}")
                # Рекурсивно ищем все JAR файлы в базовой версии
                for root, dirs, files in os.walk(base_libraries_dir):
                    for file in files:
                        if file.endswith('.jar'):
                            base_lib_path = os.path.join(root, file)
                            if base_lib_path not in classpath:
                                classpath.append(base_lib_path)
                                logging.debug(f"Добавлена библиотека из базовой версии: {file}")
        
        # Для ванильных версий тоже добавляем все JAR библиотеки (не только нативные)
        if not inherits:
            logging.info(f"Добавляем все библиотеки для ванильной версии {version_id}")
            # Рекурсивно ищем все JAR файлы в папке libraries
            for root, dirs, files in os.walk(libraries_dir):
                for file in files:
                    if file.endswith('.jar'):
                        lib_path = os.path.join(root, file)
                        if lib_path not in classpath:
                            classpath.append(lib_path)
                            logging.debug(f"Добавлена библиотека: {file}")

        # Получаем путь к ресурсам
        asset_index = version_data.get('assetIndex', {}).get('id')
        if not asset_index:
            # Если нет assetIndex, используем базовую версию
            inherits = version_data.get('inheritsFrom')
            if inherits:
                base_data = fetch_version_data(inherits)
                if base_data and 'assetIndex' in base_data:
                    asset_index = base_data['assetIndex']['id']
                    logging.info(f"Используем assetIndex из базовой версии: {asset_index}")
                else:
                    logging.error("Не удалось получить assetIndex")
                    return
            else:
                logging.error("Не удалось получить assetIndex")
                return
        
        logging.info("Формирование команды запуска...")
        java_args = [
            f'-Xmx{ram}G',
            '-XX:+UnlockExperimentalVMOptions',
            '-XX:+UseG1GC',
            '-XX:G1NewSizePercent=20',
            '-XX:G1ReservePercent=20',
            '-XX:MaxGCPauseMillis=50',
            '-XX:G1HeapRegionSize=32M',
            '-Djava.library.path=' + natives_dir,
            '-cp', os.pathsep.join(classpath),
        ]

        # Современные аргументы из version.json (особенно нужны для Fabric)
        # Если есть сохранённый аккаунт с токеном — используем его
        accounts = load_accounts()
        if accounts:
            acc = accounts[0]
            saved_name = acc.get('username') or username
            saved_uuid_nodash = acc.get('uuid')
            saved_access = acc.get('accessToken') or '0'
        else:
            saved_name = username
            saved_uuid_nodash = generate_offline_uuid(username, slim=get_saved_skin_is_slim()).replace('-', '')
            saved_access = '0'

        ctx = {
            'auth_player_name': saved_name,
            'version_name': version_id,
            'game_directory': minecraft_directory,
            'assets_root': os.path.join(minecraft_directory, 'assets'),
            'assets_index_name': asset_index,
            'auth_uuid': saved_uuid_nodash,
            'auth_access_token': saved_access,
            'clientid': '0',
            'user_type': 'legacy',
            'version_type': version_data.get('type', 'release')
        }

        game_args = [
            '--username', ctx['auth_player_name'],
            '--version', ctx['version_name'],
            '--gameDir', ctx['game_directory'],
            '--assetsDir', ctx['assets_root'],
            '--assetIndex', ctx['assets_index_name'],
            '--uuid', ctx['auth_uuid'],
            '--accessToken', ctx['auth_access_token'],
            '--clientId', ctx['clientid'],
            '--xuid', '0',
            '--userType', ctx['user_type']
        ]

        # Если присутствует modern-формат arguments, используем его
        arguments = version_data.get('arguments')
        if arguments:
            jvm_from_profile = _resolve_argument_items(arguments.get('jvm'), ctx)
            if jvm_from_profile:
                # Удаляем -Xmx/-Xms из профиля и принудительно задаём объём ОЗУ из настроек
                filtered_jvm = []
                for arg in jvm_from_profile:
                    if isinstance(arg, str) and (arg.startswith('-Xmx') or arg.startswith('-Xms')):
                        continue
                    filtered_jvm.append(arg)
                java_args = [f'-Xmx{ram}G'] + filtered_jvm + ['-Djava.library.path=' + natives_dir, '-cp', os.pathsep.join(classpath)]
            game_from_profile = _resolve_argument_items(arguments.get('game'), ctx)
            if game_from_profile:
                game_args = game_from_profile

        command = ['java'] + java_args + [version_data.get('mainClass', 'net.minecraft.client.main.Main')] + game_args

        # Убираем флаги которые могут вызывать конфликты в новых версиях
        problematic_flags = ['--demo', '--quickPlayPath', '--quickPlaySingleplayer', '--quickPlayMultiplayer', '--quickPlayRealms']
        
        for flag in problematic_flags:
            while flag in command:
                idx = command.index(flag)
                command.pop(idx)  # Убираем сам флаг
                # Если следующий элемент не флаг (не начинается с --), убираем и его как аргумент
                if idx < len(command) and not command[idx].startswith('--'):
                    command.pop(idx)
                logging.info(f"Убран проблемный флаг: {flag}")
        
        logging.info("Проверка конфликтующих аргументов завершена")

        # Убираем авто-подстановку ресурс-пака, чтобы избежать крашей при его отсутствии

        logging.info("🚀 Запуск игры...")
        logging.info(f"📋 Аргументы игры: {' '.join([arg for arg in command if arg.startswith('--')])}")
        logging.debug(f'📝 Полная команда запуска: {" ".join(command)}')
        
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            
            while True:
                output = process.stdout.readline()
                if output == b'' and process.poll() is not None:
                    break
                if output:
                    logging.info(output.strip().decode())
                    
            _, stderr = process.communicate()
            if stderr:
                logging.error(f"Ошибка при запуске: {stderr.decode()}")
            else:
                logging.info(f"Minecraft {version_id} успешно запущен")
                
        except Exception as e:
            logging.error(f"Ошибка при запуске Minecraft: {str(e)}")
            return
            
    except Exception as e:
        logging.error(f"Критическая ошибка при запуске: {str(e)}")
        return

# Функция для получения данных версии Minecraft
def fetch_version_data(version_id):
    # Сначала пытаемся найти в официальном манифесте
    manifest = fetch_mojang_manifest()
    if manifest:
        version_info = next((v for v in manifest['versions'] if v['id'] == version_id), None)
        if version_info:
            response = requests.get(version_info['url'], timeout=DEFAULT_HTTP_TIMEOUT)
            if response.status_code == 200:
                return response.json()
            else:
                logging.error("Не удалось загрузить данные версии из манифеста.")

    # Фоллбек: читаем локальный profile JSON (например, Fabric)
    local = fetch_local_version_data(version_id)
    if local:
        return local

    logging.error(f"Версия {version_id} не найдена ни в манифесте, ни локально.")
    return None

class LauncherSettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки лаунчера")
        self.setFixedSize(340, 260)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: #333333; color: #ffffff;")
        # Кнопка закрытия (с корректной привязкой и поверх контента)
        try:
            self.close_btn = QtWidgets.QPushButton(self)
            self.close_btn.setFixedSize(25, 25)
            self.close_btn.setStyleSheet("""
                QPushButton { background-color:rgba(68,71,90,0); color:#ffffff; border:none; border-radius:4px; }
                QPushButton:hover { background-color:rgb(250,44,61); }
            """)
            close_icon = QtGui.QIcon(os.path.join(IMAGES_DIR, "Close.png"))
            self.close_btn.setIcon(close_icon)
            self.close_btn.setIconSize(QtCore.QSize(25, 25))
            self.close_btn.clicked.connect(self.close)
            attach_close_button(self, self.close_btn, margin=5)
            self.close_btn.raise_()
        except Exception:
            pass
        
        self.load_settings()
        
        # Настройка оперативной памяти (умная граница)
        self.ram_label = QtWidgets.QLabel("ОЗУ для Minecraft (ГБ):")
        self.ram_spin = QtWidgets.QSpinBox()
        total_gb = get_total_ram_gb()
        # Оставляем 2 ГБ системе, минимум 1 ГБ для выбора
        max_gb = max(1, total_gb - 2)
        self.ram_spin.setRange(1, max_gb)
        self.ram_spin.setValue(min(self.settings.get('ram', 2), max_gb))
        
        # Добавляем чекбокс для включения/выключения снепшотов
        self.snapshots_checkbox = QtWidgets.QCheckBox("Показывать снепшоты")
        self.snapshots_checkbox.setChecked(self.settings.get('show_snapshots', False))

        # Новый чекбокс: показывать Fabric в списках версий (по умолчанию выключен)
        self.fabric_checkbox = QtWidgets.QCheckBox("Показывать Fabric версии")
        self.fabric_checkbox.setChecked(self.settings.get('show_fabric', False))

        # Консоль разработчика удалена
        
        # Кнопки сохранения/отмены
        self.save_button = QtWidgets.QPushButton("Сохранить")
        self.cancel_button = QtWidgets.QPushButton("Отмена")
        
        # Стилизация
        button_style = """
            QPushButton {
                background-color: #61afef;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #508acc;
            }
        """
        self.save_button.setStyleSheet(button_style)
        self.cancel_button.setStyleSheet(button_style)
        self.ram_spin.setStyleSheet("background-color: #44475a; color: #ffffff;")
        self.snapshots_checkbox.setStyleSheet("color: #ffffff;")

        # Расположение элементов
        layout = QtWidgets.QVBoxLayout()
        # Размещаем подпись ОЗУ и поле выбора вплотную (в одну строку)
        ram_layout = QtWidgets.QHBoxLayout()
        ram_layout.setContentsMargins(0, 0, 0, 0)
        ram_layout.setSpacing(0)
        ram_layout.addWidget(self.ram_label)
        ram_layout.addWidget(self.ram_spin)
        layout.addLayout(ram_layout)
        layout.addWidget(self.snapshots_checkbox)
        layout.addWidget(self.fabric_checkbox)
        
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Подключение сигналов
        self.save_button.clicked.connect(self.save_settings)
        self.cancel_button.clicked.connect(self.reject)

    def load_settings(self):
        self.settings_path = os.path.join(LAUNCHER_FILES_DIR, "launcher_settings.json")
        try:
            with open(self.settings_path, 'r') as f:
                self.settings = json.load(f)
        except:
            self.settings = {'ram': 2, 'show_snapshots': False, 'show_fabric': False}

    def save_settings(self):
        self.settings['ram'] = self.ram_spin.value()
        self.settings['show_snapshots'] = self.snapshots_checkbox.isChecked()
        self.settings['show_fabric'] = self.fabric_checkbox.isChecked()
        with open(self.settings_path, 'w') as f:
            json.dump(self.settings, f)
        self.accept()

    def open_console(self):
        QMessageBox.information(self, "Консоль", "Консоль пока не реализована")

    # Удалены методы работы с консолью разработчика

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    try:
        # Show splash screen
        splash = SplashScreen()
        if splash.exec_() == QtWidgets.QDialog.Accepted:
            MainWindow = QtWidgets.QMainWindow()
            ui = Ui_MainWindow()
            ui.setupUi(MainWindow)
            MainWindow.show()
        sys.exit(app.exec_())
    finally:
        remove_hosts_redirects()