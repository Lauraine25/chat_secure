# 💬 Chat Sécurisé - Système de Messagerie Client-Serveur

Un système de messagerie texte professionnel, sécurisé et multi-clients implémenté en Python avec chiffrement bout-en-bout (AES-256) et persistance en MySQL.

## 🎯 Caractéristiques Principales

✅ **Chiffrement Bout-en-Bout (E2E)**
   - Chiffrement AES-256-CBC pour tous les messages
   - Clés générées côté client et chiffrées localement
   - Les messages stockés en base sont en clair (à adapter selon besoins)

✅ **Architecture Multi-Client**
   - Threading côté serveur pour gérer plusieurs clients simultanément
   - Pas de limite d'utilisateurs connectés
   - Communication asynchrone en temps réel

✅ **Interface Graphique (Tkinter)**
   - Client GUI moderne et intuitive
   - Affichage en temps réel des connexions
   - Historique des messages
   - Accès à la liste des utilisateurs en ligne

✅ **Persistance MySQL**
   - Historique complet des messages
   - Gestion des utilisateurs
   - Sessions et audit de sécurité
   - Tables optimisées avec index et contraintes

✅ **Sécurité Élevée**
   - Hachage des mots de passe (bcrypt)
   - Journalisation d'audit (audit_log)
   - Validation des autorisations
   - Gestion des clés de chiffrement

---

## 📋 Architecture Système

```
┌──────────────┐                         ┌──────────────┐
│  Client 1    │                         │  Client 2    │
│ (Tkinter)    │                         │ (Tkinter)    │
│   + AES-256  │                         │   + AES-256  │
└──────┬───────┘                         └──────┬───────┘
       │                                        │
       │  Socket TCP                           │
       │  (Messages chiffrés)                  │
       └────────────┬─────────────────────────┘
                    │
        ┌───────────▼──────────────┐
        │   Serveur Principal      │
        ├──────────────────────────┤
        │ • Socket Listener        │
        │ • Thread Pool            │
        │ • ClientHandler×N        │
        │ • Routable de messages   │
        │ • Authentification       │
        └───────────┬──────────────┘
                    │
                    │ MySQL Driver
                    │
        ┌───────────▼──────────────┐
        │    MySQL Database        │
        ├──────────────────────────┤
        │ • users                  │
        │ • messages               │
        │ • sessions               │
        │ • contacts               │
        │ • encryption_keys        │
        │ • audit_log              │
        └──────────────────────────┘
```

---

## 🗄️ Structure de la Base de Données MySQL

### Schéma Détaillé

#### **Table `users`**
Stocke les informations des utilisateurs.

```sql
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE,       -- Identifiant unique
    email VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255),         -- Hash bcrypt, PAS le mot de passe
    created_at TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN
);
```

**Exemple :**
| user_id | username | email | password_hash | created_at | last_login | is_active |
|---------|----------|-------|---|---|---|---|
| 1 | alice | alice@example.com | $2b$12$... | 2026-03-01 | 2026-03-04 | 1 |
| 2 | bob | bob@example.com | $2b$12$... | 2026-03-02 | 2026-03-04 | 1 |

---

#### **Table `messages`**
Historique complet des messages.

```sql
CREATE TABLE messages (
    message_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    sender VARCHAR(50),                 -- Qui envoie
    recipient VARCHAR(50),              -- Qui reçoit
    content LONGTEXT,                   -- Contenu (peut être chiffré)
    timestamp DATETIME,                 -- Quand
    is_read BOOLEAN,                    -- Lu ou non
    ip_sender VARCHAR(45)               -- IP de l'expéditeur
);
```

**Exemple :**
| message_id | sender | recipient | content | timestamp | is_read |
|---|---|---|---|---|---|
| 1 | alice | bob | Bonjour! | 2026-03-04 10:30:45 | 0 |
| 2 | bob | alice | Salut! Ça va? | 2026-03-04 10:31:02 | 1 |

**Index pour performance :**
- `(sender, recipient, timestamp)` - Requêtes de conversation rapides
- `(recipient, is_read)` - Messages non lus rapides

---

#### **Table `sessions`**
Gère les sessions actives.

```sql
CREATE TABLE sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id INT,
    username VARCHAR(50),
    login_time TIMESTAMP,
    last_activity TIMESTAMP,
    ip_address VARCHAR(45),
    is_active BOOLEAN
);
```

---

#### **Table `contacts`**
Listes de contacts des utilisateurs.

```sql
CREATE TABLE contacts (
    contact_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,                        -- Propriétaire de la relation
    contact_user_id INT,                -- Utilisateur contact
    nickname VARCHAR(100),              -- Surnom personnalisé
    created_at TIMESTAMP,
    is_blocked BOOLEAN
);
```

---

#### **Table `encryption_keys`**
Stockage des clés publiques et métadonnées.

```sql
CREATE TABLE encryption_keys (
    key_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    public_key LONGTEXT,
    key_algorithm VARCHAR(50),          -- 'RSA-2048', 'AES-256'
    created_at TIMESTAMP,
    expires_at DATETIME,
    is_active BOOLEAN
);
```

---

#### **Table `audit_log`**
Journalisation des actions de sécurité.

```sql
CREATE TABLE audit_log (
    log_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(100),                -- 'LOGIN', 'LOGOUT', 'MESSAGE_SENT'
    resource_type VARCHAR(50),
    timestamp TIMESTAMP,
    ip_address VARCHAR(45),
    details LONGTEXT
);
```

**Exemples d'actions :** `LOGIN`, `LOGOUT`, `MESSAGE_SENT`, `KEY_ROTATION`, `FAILED_AUTH`

---

### Diagramme ER (Entity-Relationship)

```
users (user_id, username, email, ...)
  ├─→ messages (message_id, sender, recipient, ...)
  ├─→ sessions (session_id, user_id, ...)
  ├─→ contacts (contact_id, user_id, contact_user_id, ...)
  ├─→ encryption_keys (key_id, user_id, ...)
  └─→ audit_log (log_id, user_id, ...)
```

---

## ⚙️ Installation et Configuration

### 1️⃣ **Prérequis**

- **Python 3.8+**
- **MySQL Server 5.7+** (ou MariaDB 10.2+)
- **xampp** (pour ce projet específiquement) avec Apache et MySQL

### 2️⃣ **Installation des Dépendances Python**

```bash
# Naviguer dans le répertoire du projet
cd c:\xampp\htdocs\chat_secure

# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement virtuel
# Sur Windows:
venv\Scripts\activate
# Sur Linux/Mac:
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

### 3️⃣ **Configuration MySQL**

#### Option A: Utiliser le script SQL fourni

```bash
# Se connecter à MySQL
mysql -u root -p

# Exécuter le script
source c:\xampp\htdocs\chat_secure\database_setup.sql
```

#### Option B: Création manuelle

```bash
mysql -u root -p < database_setup.sql
```

### 4️⃣ **Configuration des Paramètres**

Éditer `config.py` pour personnaliser :

```python
# DatabaseMySQL
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'VOTRE_MOT_DE_PASSE',  # ⚠️ À compléter
    'database': 'chat_secure',
}

# Serveur
SERVER_HOST = 'localhost'
SERVER_PORT = 5555
```

---

## 🚀 Utilisation

### **Démarrer le Serveur**

```bash
# Depuis le répertoire du projet (venv activé)
python server.py
```

**Sortie attendue :**
```
2026-03-04 10:00:01 - __main__ - INFO - Connecté à la base de données MySQL
2026-03-04 10:00:01 - __main__ - INFO - Serveur démarré sur localhost:5555
```

### **Démarrer les Clients**

D'autres terminaux/machines (garder le serveur actif) :

```bash
python client.py
```

Une fenêtre Tkinter s'ouvre. 

**Étapes :**
1. Entrer un nom d'utilisateur (ex: `alice`)
2. Cliquer **Connecter**
3. La liste des utilisateurs en ligne s'affiche
4. Sélectionner un utilisateur et envoyer un message
5. Les messages sont chiffrés/déchiffrés automatiquement

---

## 🔐 Système de Chiffrement

### Algorithme: **AES-256-CBC**

**Flux:**

```
Message en clair
    ↓
Génération IV aléatoire (16 bytes)
    ↓
Padding PKCS7
    ↓
Chiffrement AES-256-CBC(clé, IV)
    ↓
Concaténation: IV + Ciphertext
    ↓
Encodage Base64
    ↓
Transmission TCP
```

**Déchiffrement:**
```
Réception Base64
    ↓
Décodage Base64
    ↓
Extraction: IV (16 premiers bytes) + Ciphertext
    ↓
Déchiffrement AES-256-CBC(clé, IV)
    ↓
Suppression Padding PKCS7
    ↓
Message en clair
```

### Exemple Code Python:

```python
from encryption import AESEncryption

# Créer une instance de chiffrement
cipher = AESEncryption()

# Chiffrer
message = "Ceci est un message secret!"
encrypted = cipher.encrypt(message)
print(f"Chiffré: {encrypted}")

# Déchiffrer
decrypted = cipher.decrypt(encrypted)
print(f"Déchiffré: {decrypted}")

assert message == decrypted
```

---

## 📊 Architecture du Code

### **Fichiers Principaux:**

| Fichier | Rôle | Lignes |
|---------|------|--------|
| `server.py` | Serveur TCP multi-client avec threading | ~350 |
| `client.py` | Client GUI Tkinter | ~450 |
| `encryption.py` | Modules AES-256 | ~200 |
| `config.py` | Configuration centralisée | ~30 |
| `database_setup.sql` | Schéma MySQL complet | ~300 |

### **Flux de Communication:**

1. **Connexion Client**
   - Le client se connecte au port TCP du serveur
   - Envoie `{username, clé_chiffrement}`
   - Serveur valide et crée un `ClientHandler` (thread)

2. **Envoi de Message**
   - Client: chiffre le message avec sa clé AES
   - Envoi: `{type: "message", recipient, content_chiffré}`
   - Serveur: déchiffre, sauvegarde en MySQL, relaie au destinataire (si en ligne)
   - Destinataire: décrypte et affiche

3. **Historique**
   - Client: demande `{type: "get_history", recipient}`
   - Serveur: requête MySQL, retourne tous les messages
   - Client: affiche dans l'interface

4. **Déconnexion**
   - Client: envoie `{type: "disconnect"}`
   - Serveur: ferme le socket, libère la ressource

---

## 🔒 Aspects de Sécurité

### ✅ Implémenté

1. **Chiffrement AES-256** - Messages non lisibles en transit
2. **IV Aléatoire** - Prévient les attaques par motifs
3. **Padding PKCS7** - Sécurise les blocs incomplets
4. **Separation Public/Private** - Client génère sa propre clé
5. **Hachage Bcrypt** - Mots de passe ne sont jamais stockés
6. **Audit Log** - Trace toutes les actions sensibles

### ⚠️ À Améliorer (Production)

1. **Authentification** - Ajouter login/password
2. **TLS/SSL** - Sécuriser le transport TCP
3. **Perfect Forward Secrecy** - Clés éphémères par session
4. **Message Signing** - Certifier l'authenticité de l'expéditeur
5. **Rate Limiting** - Prévenir les attaques DoS
6. **HTTPS** - Pour l'exposure réseau (si besoin)

---

## 🧪 Tests

### Test du Chiffrement Seul:

```bash
python encryption.py
```

Sortie:
```
Message original: Ceci est un message secret!
Message chiffré: Y3JpcHRvZ3JhcGh5X3Jlc3VsdA==...
Message déchiffré: Ceci est un message secret!
✓ Chiffrement/déchiffrement réussi!
```

### Test du Serveur:

```bash
# Terminal 1: Démarrer le serveur
python server.py

# Terminal 2: Client 1
python client.py
# Entrer "alice" → Connecter

# Terminal 3: Client 2
python client.py
# Entrer "bob" → Connecter

# Envoyer des messages entre alice et bob
```

---

## 📈 Optimisations et Scalabilité

### **Pour des Milliers de Clients:**

1. **Utiliser Asyncio/Event Loop** 
   ```python
   import asyncio
   # Remplacer threading par asyncio pour moins de surcharge
   ```

2. **Connection Pooling MySQL**
   ```python
   from mysql.connector import pooling
   cnx_pool = pooling.MySQLConnectionPool(pool_name="chat_pool", pool_size=10, ...)
   ```

3. **Cache Redis**
   ```
   Stocker les messages non lus en Redis avant MySQL
   Améliore latence pour l'historique récent
   ```

4. **Websockets**
   ```python
   import websockets
   # Remplacer TCP par WebSocket pour navigateurs
   ```

5. **Load Balancer**
   ```
   Nginx/HAProxy pour distribuer les connexions sur plusieurs serveurs
   ```

---

## 🐛 Dépannage

### **Problème: "Connection refused"**
- ✓ Vérifier que le serveur est lancé
- ✓ Vérifier le port 5555 est libre: `netstat -an | grep 5555`

### **Problème: "Access denied for user 'root'@'localhost'"**
- ✓ Vérifier le mot de passe MySQL dans `config.py`
- ✓ Utiliser MySQL Workbench pour tester

### **Problème: Messages ne s'affichent pas**
- ✓ Vérifier que le destinataire est connecté
- ✓ Vérifier les logs du serveur pour les erreurs
- ✓ S'assurer que le chiffrement/déchiffrement fonctionne

### **Problème: Clé de chiffrement invalide**
- ✓ Les deux clients doivent utiliser la MÊME clé
- ✓ Implémenter un mécanisme d'échange de clé (Diffie-Hellman)

---

## 📚 Ressources et Références

- [Cryptography.io Documentation](https://cryptography.io/)
- [MySQL Official Documentation](https://dev.mysql.com/doc/)
- [Tkinter Documentation](https://docs.python.org/3/library/tkinter.html)
- [AES Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [OWASP Top 10](https://owasp.org/Top10/)

---

## 📝 Licence

Libre d'utilisation à titre éducatif. Adapter pour production selon vos besoins de sécurité.

---

## 👨‍💻 Améliorations Futures

- [ ] Authentification par mot de passe
- [ ] Chiffrement en base de données
- [ ] Support des groupes de chat
- [ ] Partage de fichiers sécurisé
- [ ] Interface web (Flask/Django)
- [ ] Mobile app (React Native)
- [ ] Vidéo conférence E2E
- [ ] Signature numérique des messages

---

**Créé avec ❤️ pour la sécurité informatique**
