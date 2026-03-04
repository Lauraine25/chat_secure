"""
Configuration centralisée pour le système de messagerie Client-Serveur
"""

# Configuration Serveur
SERVER_HOST = 'localhost'
SERVER_PORT = 5555
MAX_BUFFER_SIZE = 4096
HEARTBEAT_INTERVAL = 30  # En secondes

# Configuration Base de données MySQL
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # À compléter avec votre mot de passe MySQL
    'database': 'chat_secure',
    'charset': 'utf8mb4',
    'autocommit': True
}

# Configuration Chiffrement
ENCRYPTION_ALGORITHM = 'AES'
KEY_SIZE = 32  # 256 bits pour AES
ENCODING = 'utf-8'

# Configuration Logging
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'INFO'

# Configuration Client
CLIENT_RECONNECT_TIMEOUT = 5  # Tentatives de reconnexion
MAX_RECONNECT_ATTEMPTS = 5
