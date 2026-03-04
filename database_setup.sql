-- ============================================================================
-- Script de création de la base de données MySQL pour le chat sécurisé
-- ============================================================================

-- Créer la base de données
CREATE DATABASE IF NOT EXISTS chat_secure 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- Utiliser la base de données
USE chat_secure;

-- ============================================================================
-- TABLE: users
-- Stocke les informations des utilisateurs enregistrés
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Identifiant unique de l\'utilisateur',
    username VARCHAR(50) NOT NULL UNIQUE COMMENT 'Nom d\'utilisateur (login)',
    email VARCHAR(100) NOT NULL UNIQUE COMMENT 'Adresse email',
    password_hash VARCHAR(255) NOT NULL COMMENT 'Hash du mot de passe (bcrypt ou similaire)',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Date de création du compte',
    last_login TIMESTAMP NULL COMMENT 'Dernière connexion',
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Statut du compte',
    
    INDEX idx_username (username),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_unicode_ci
COMMENT='Table des utilisateurs enregistrés';

-- ============================================================================
-- TABLE: messages
-- Stocke l'historique complet des messages chiffrés
-- ============================================================================
CREATE TABLE IF NOT EXISTS messages (
    message_id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Identifiant unique du message',
    sender VARCHAR(50) NOT NULL COMMENT 'Nom d\'utilisateur de l\'expéditeur',
    recipient VARCHAR(50) NOT NULL COMMENT 'Nom d\'utilisateur du destinataire',
    content LONGTEXT NOT NULL COMMENT 'Contenu chiffré avec la clé de l\'expéditeur (AES-256)',
    content_encrypted_for_recipient LONGTEXT COMMENT 'Même contenu chiffré avec la clé du destinataire (AES-256)',
    timestamp DATETIME NOT NULL COMMENT 'Date et heure d\'envoi du message',
    is_read BOOLEAN DEFAULT FALSE COMMENT 'Statut de lecture du message',
    ip_sender VARCHAR(45) COMMENT 'Adresse IP de l\'expéditeur (IPv4 ou IPv6)',
    
    INDEX idx_sender (sender),
    INDEX idx_recipient (recipient),
    INDEX idx_timestamp (timestamp),
    INDEX idx_conversation (sender, recipient),
    INDEX idx_is_read (is_read),
    CONSTRAINT fk_sender FOREIGN KEY (sender) REFERENCES users(username) 
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_recipient FOREIGN KEY (recipient) REFERENCES users(username) 
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_unicode_ci
COMMENT='Historique des messages entre utilisateurs';

-- ============================================================================
-- TABLE: sessions
-- Gère les sessions des utilisateurs connectés
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(128) PRIMARY KEY COMMENT 'Identifiant de session (UUID)',
    user_id INT NOT NULL COMMENT 'Référence à l\'utilisateur',
    username VARCHAR(50) NOT NULL COMMENT 'Nom d\'utilisateur',
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Heure de connexion',
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Dernière activité',
    ip_address VARCHAR(45) COMMENT 'Adresse IP de connexion',
    user_agent VARCHAR(255) COMMENT 'User-Agent du client',
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Statut de la session',
    
    INDEX idx_username (username),
    INDEX idx_user_id (user_id),
    INDEX idx_last_activity (last_activity),
    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES users(user_id) 
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_unicode_ci
COMMENT='Sessions actives des utilisateurs';

-- ============================================================================
-- TABLE: contacts
-- Gère les listes de contacts (amis)
-- ============================================================================
CREATE TABLE IF NOT EXISTS contacts (
    contact_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Identifiant unique du contact',
    user_id INT NOT NULL COMMENT 'Utilisateur propriétaire de la liste',
    contact_user_id INT NOT NULL COMMENT 'Identifiant de l\'utilisateur contact',
    nickname VARCHAR(100) COMMENT 'Surnom personnalisé du contact',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Date d\'ajout du contact',
    is_blocked BOOLEAN DEFAULT FALSE COMMENT 'Contact bloqué ?',
    
    INDEX idx_user_id (user_id),
    INDEX idx_contact_user_id (contact_user_id),
    UNIQUE KEY unique_contact (user_id, contact_user_id),
    CONSTRAINT fk_contact_user FOREIGN KEY (user_id) REFERENCES users(user_id) 
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_contact_contact FOREIGN KEY (contact_user_id) REFERENCES users(user_id) 
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_unicode_ci
COMMENT='Listes de contacts des utilisateurs';

-- ============================================================================
-- TABLE: encryption_keys
-- Stocke les clés de chiffrement et métadonnées de sécurité
-- ============================================================================
CREATE TABLE IF NOT EXISTS encryption_keys (
    key_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Identifiant de la clé',
    user_id INT NOT NULL COMMENT 'Utilisateur propriétaire de la clé',
    public_key LONGTEXT NOT NULL COMMENT 'Clé publique de l\'utilisateur',
    key_algorithm VARCHAR(50) NOT NULL DEFAULT 'RSA-2048' COMMENT 'Algorithme utilisé',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Date de création',
    expires_at DATETIME COMMENT 'Date d\'expiration de la clé',
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Clé active ?',
    
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at),
    CONSTRAINT fk_key_user FOREIGN KEY (user_id) REFERENCES users(user_id) 
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_unicode_ci
COMMENT='Clés de chiffrement public des utilisateurs';

-- ============================================================================
-- TABLE: audit_log
-- Journalise les actions importantes pour la sécurité
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Identifiant du log',
    user_id INT COMMENT 'Utilisateur ayant effectué l\'action',
    action VARCHAR(100) NOT NULL COMMENT 'Type d\'action (LOGIN, LOGOUT, MESSAGE_SENT, etc.)',
    resource_type VARCHAR(50) COMMENT 'Type de ressource affectée',
    resource_id VARCHAR(100) COMMENT 'ID de la ressource',
    details LONGTEXT COMMENT 'Détails supplémentaires',
    ip_address VARCHAR(45) COMMENT 'Adresse IP source',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Date/heure de l\'action',
    
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_timestamp (timestamp),
    INDEX idx_resource (resource_type, resource_id),
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(user_id) 
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_unicode_ci
COMMENT='Journalisation des actions de sécurité';

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Vue: conversation (derniers messages entre utilisateurs)
CREATE OR REPLACE VIEW IF NOT EXISTS conversation_summary AS
SELECT 
    CASE 
        WHEN sender = @username THEN recipient 
        ELSE sender 
    END AS other_user,
    MAX(timestamp) AS last_message_time,
    SUM(CASE WHEN is_read = FALSE AND recipient = @username THEN 1 ELSE 0 END) AS unread_count
FROM messages
WHERE (sender = @username OR recipient = @username)
GROUP BY other_user
ORDER BY last_message_time DESC;

-- Vue: utilisateurs actifs
CREATE OR REPLACE VIEW IF NOT EXISTS active_users AS
SELECT 
    u.user_id,
    u.username,
    u.email,
    s.session_id,
    s.login_time,
    s.last_activity,
    s.ip_address
FROM users u
INNER JOIN sessions s ON u.user_id = s.user_id
WHERE s.is_active = TRUE;

-- ============================================================================
-- PROCÉDURES STOCKÉES
-- ============================================================================

-- Procédure: Enregistrer un message avec logging
DELIMITER //

CREATE PROCEDURE IF NOT EXISTS sp_save_message(
    IN p_sender VARCHAR(50),
    IN p_recipient VARCHAR(50),
    IN p_content LONGTEXT,
    IN p_ip_sender VARCHAR(45)
)
BEGIN
    DECLARE sender_id INT;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Erreur lors de l\'enregistrement du message';
    END;
    
    START TRANSACTION;
    
    -- Vérifier que l'expéditeur existe
    SELECT user_id INTO sender_id FROM users WHERE username = p_sender;
    
    IF sender_id IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Expéditeur inexistant';
    END IF;
    
    -- Insérer le message
    INSERT INTO messages (sender, recipient, content, timestamp, is_read, ip_sender)
    VALUES (p_sender, p_recipient, p_content, NOW(), FALSE, p_ip_sender);
    
    -- Journaliser l'action
    INSERT INTO audit_log (user_id, action, resource_type, resource_id, ip_address)
    VALUES (sender_id, 'MESSAGE_SENT', 'MESSAGE', LAST_INSERT_ID(), p_ip_sender);
    
    COMMIT;
END //

DELIMITER ;

-- Procédure: Marquer les messages comme lus
DELIMITER //

CREATE PROCEDURE IF NOT EXISTS sp_mark_messages_as_read(
    IN p_recipient VARCHAR(50),
    IN p_sender VARCHAR(50)
)
BEGIN
    UPDATE messages
    SET is_read = TRUE
    WHERE recipient = p_recipient AND sender = p_sender AND is_read = FALSE;
END //

DELIMITER ;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Trigger: Mettre à jour last_login lors d'une connexion
DELIMITER //

CREATE TRIGGER IF NOT EXISTS trigger_update_last_login
AFTER INSERT ON sessions
FOR EACH ROW
BEGIN
    UPDATE users
    SET last_login = NEW.login_time
    WHERE user_id = NEW.user_id;
END //

DELIMITER ;

-- Trigger: Nettoyer les sessions expirées
DELIMITER //

CREATE TRIGGER IF NOT EXISTS trigger_cleanup_sessions
AFTER UPDATE ON sessions
FOR EACH ROW
BEGIN
    DELETE FROM sessions
    WHERE is_active = FALSE 
    AND last_activity < DATE_SUB(NOW(), INTERVAL 24 HOUR);
END //

DELIMITER ;

-- ============================================================================
-- DONNÉES INITIALES (optionnel)
-- ============================================================================

-- Créer quelques utilisateurs de test
INSERT IGNORE INTO users (username, email, password_hash) VALUES
('alice', 'alice@example.com', '$2b$12$abcdefghijklmnopqrstuvwxyz'),
('bob', 'bob@example.com', '$2b$12$abcdefghijklmnopqrstuvwxyz'),
('charlie', 'charlie@example.com', '$2b$12$abcdefghijklmnopqrstuvwxyz');

-- ============================================================================
-- STATISTIQUES ET MAINTENANCE
-- ============================================================================

-- Analyser les tables pour optimiser les requêtes
ANALYZE TABLE users;
ANALYZE TABLE messages;
ANALYZE TABLE sessions;
ANALYZE TABLE contacts;
ANALYZE TABLE encryption_keys;
ANALYZE TABLE audit_log;
