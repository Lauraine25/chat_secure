#!/usr/bin/env python3
"""
Script d'installation et configuration du système de messagerie
Automatise la création de la base de données et la vérification des dépendances
"""

import os
import sys
import mysql.connector
from pathlib import Path
import subprocess

# Couleurs pour le terminal
class Colors:
    OKGREEN = '\033[92m'
    OKBLUE = '\033[94m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKBLUE}{text}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKBLUE}{'='*60}{Colors.ENDC}\n")

def print_success(text):
    print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")

def print_warning(text):
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")

def check_python_version():
    """Vérifie la version de Python"""
    print_header("Vérification de Python")
    
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print_success(f"Python {version.major}.{version.minor}.{version.micro} détecté")
        return True
    else:
        print_error(f"Python 3.8+ requis, {version.major}.{version.minor} trouvé")
        return False

def check_dependencies():
    """Vérifie les dépendances Python"""
    print_header("Vérification des Dépendances Python")
    
    required = {
        'cryptography': 'Pour le chiffrement AES-256',
        'mysql.connector': 'Pour MySQL',
        'tkinter': 'Pour l\'interface graphique'
    }
    
    missing = []
    for module, description in required.items():
        try:
            if module == 'tkinter':
                import tkinter
            else:
                __import__(module)
            print_success(f"{module}: installé - {description}")
        except ImportError:
            print_error(f"{module}: MANQUANT - {description}")
            missing.append(module)
    
    if missing:
        print_warning("\nDépendances manquantes détectées")
        response = input("\nInstaller les dépendances manquantes? (o/n): ").lower()
        if response == 'o':
            install_dependencies()
            return True
        return False
    
    return True

def install_dependencies():
    """Installe les dépendances manquantes"""
    print_header("Installation des Dépendances")
    
    try:
        requirement_file = Path(__file__).parent / 'requirements.txt'
        if requirement_file.exists():
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', str(requirement_file)])
            print_success("Dépendances installées avec succès")
            return True
    except Exception as e:
        print_error(f"Erreur lors de l'installation: {e}")
        print_warning("Installer manuellement: pip install -r requirements.txt")
        return False

def check_mysql_connection(host, user, password):
    """Teste la connexion MySQL"""
    try:
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password
        )
        connection.close()
        return True
    except mysql.connector.Error as e:
        print_error(f"Erreur MySQL: {e}")
        return False

def setup_database():
    """Configure la base de données MySQL"""
    print_header("Configuration de la Base de Données MySQL")
    
    # Demander les informations de connexion
    host = input("Hôte MySQL [localhost]: ").strip() or 'localhost'
    user = input("Utilisateur MySQL [root]: ").strip() or 'root'
    password = input("Mot de passe MySQL [vide]: ").strip() or ''
    
    # Tester la connexion
    print("\nVérification de la connexion...")
    if not check_mysql_connection(host, user, password):
        print_error("Impossible de se connecter à MySQL")
        return False
    
    print_success("Connexion MySQL établie")
    
    # Charger et exécuter le script SQL
    print("\nExécution du script d'initialisation de la base de données...")
    sql_file = Path(__file__).parent / 'database_setup.sql'
    
    if not sql_file.exists():
        print_error(f"Fichier SQL non trouvé: {sql_file}")
        return False
    
    try:
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password
        )
        cursor = connection.cursor()
        
        # Lire et exécuter le fichier SQL
        with open(sql_file, 'r', encoding='utf-8') as f:
            # Diviser les commandes SQL
            sql_text = f.read()
            
            # Exécuter la création de base de données
            cursor.execute("CREATE DATABASE IF NOT EXISTS chat_secure CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            cursor.execute("USE chat_secure;")
            
            # Créer les tables
            setup_tables(cursor)
            
            connection.commit()
            cursor.close()
            connection.close()
        
        print_success("Base de données créée avec succès")
        return True
    
    except Exception as e:
        print_error(f"Erreur lors de la création de la base de données: {e}")
        print_warning("Essayer manuellement: mysql -u root -p < database_setup.sql")
        return False

def setup_tables(cursor):
    """Crée les tables MySQL"""
    
    # Table des utilisateurs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            email VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP NULL,
            is_active BOOLEAN DEFAULT TRUE,
            INDEX idx_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)
    
    # Table des messages
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            message_id BIGINT AUTO_INCREMENT PRIMARY KEY,
            sender VARCHAR(50) NOT NULL,
            recipient VARCHAR(50) NOT NULL,
            content LONGTEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            ip_sender VARCHAR(45),
            INDEX idx_sender (sender),
            INDEX idx_recipient (recipient),
            INDEX idx_timestamp (timestamp),
            INDEX idx_conversation (sender, recipient),
            CONSTRAINT fk_sender FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE,
            CONSTRAINT fk_recipient FOREIGN KEY (recipient) REFERENCES users(username) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)
    
    # Table des sessions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id VARCHAR(128) PRIMARY KEY,
            user_id INT NOT NULL,
            username VARCHAR(50) NOT NULL,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            ip_address VARCHAR(45),
            is_active BOOLEAN DEFAULT TRUE,
            INDEX idx_username (username),
            CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)
    
    # Table des audit logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            action VARCHAR(100) NOT NULL,
            resource_type VARCHAR(50),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45),
            details LONGTEXT,
            INDEX idx_user_id (user_id),
            INDEX idx_timestamp (timestamp),
            CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)
    
    print_success("Toutes les tables créées")

def update_config():
    """Met à jour le fichier config.py avec les données de MySQL"""
    print_header("Mise à Jour de la Configuration")
    
    config_file = Path(__file__).parent / 'config.py'
    
    if not config_file.exists():
        print_error("Fichier config.py non trouvé")
        return False
    
    host = input("Hôte MySQL [localhost]: ").strip() or 'localhost'
    user = input("Utilisateur MySQL [root]: ").strip() or 'root'
    password = input("Mot de passe MySQL [vide]: ").strip() or ''
    port = input("Port MySQL [5555]: ").strip() or '5555'
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remplacer les valeurs
        content = content.replace("'host': 'localhost'", f"'host': '{host}'")
        content = content.replace("'user': 'root'", f"'user': '{user}'")
        content = content.replace("'password': ''", f"'password': '{password}'")
        content = content.replace("SERVER_PORT = 5555", f"SERVER_PORT = {port}")
        
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print_success(f"Configuration mise à jour")
        return True
    
    except Exception as e:
        print_error(f"Erreur lors de la mise à jour: {e}")
        return False

def create_test_users():
    """Crée des utilisateurs de test"""
    print_header("Création des Utilisateurs de Test")
    
    response = input("Créer des utilisateurs de test? (o/n): ").lower()
    if response != 'o':
        return True
    
    try:
        import config
        
        connection = mysql.connector.connect(**config.DB_CONFIG)
        cursor = connection.cursor()
        
        users = [
            ('alice', 'alice@example.com'),
            ('bob', 'bob@example.com'),
            ('charlie', 'charlie@example.com')
        ]
        
        for username, email in users:
            try:
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                    (username, email, '$2b$12$encrypted_password_hash_placeholder')
                )
                print_success(f"Utilisateur créé: {username}")
            except mysql.connector.Error:
                print_warning(f"Utilisateur {username} existe déjà")
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return True
    
    except Exception as e:
        print_error(f"Erreur lors de la création des utilisateurs: {e}")
        return False

def main():
    """Fonction principale d'installation"""
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}")
    print("""
╔════════════════════════════════════════════════════════════╗
║       Système de Messagerie Sécurisé - Installateur       ║
║                  Version 1.0 - 2026                       ║
╚════════════════════════════════════════════════════════════╝
    """)
    print(Colors.ENDC)
    
    # Étape 1: Python
    if not check_python_version():
        sys.exit(1)
    
    # Étape 2: Dépendances
    if not check_dependencies():
        print_warning("Certaines dépendances sont manquantes")
    
    # Étape 3: MySQL
    response = input("\nConfigurer la base de données MySQL? (o/n): ").lower()
    if response == 'o':
        if setup_database():
            update_config()
            create_test_users()
    
    # Résumé
    print_header("Installation Terminée!")
    print(f"""
{Colors.OKGREEN}Étapes suivantes:{Colors.ENDC}

1. Modifier {Colors.BOLD}config.py{Colors.ENDC} avec vos paramètres MySQL si nécessaire

2. Démarrer le serveur:
   {Colors.BOLD}python server.py{Colors.ENDC}

3. Démarrer les clients (dans d'autres terminaux):
   {Colors.BOLD}python client.py{Colors.ENDC}

4. Consulter {Colors.BOLD}README.md{Colors.ENDC} pour la documentation complète

{Colors.OKGREEN}Êtes-vous prêt à commencer? 🚀{Colors.ENDC}
    """)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_error("\nInstallation annulée par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print_error(f"Erreur fatale: {e}")
        sys.exit(1)
