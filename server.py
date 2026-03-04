"""
Serveur de messagerie multi-client
- Gère les connexions TCP avec threading
- Persiste les messages dans MySQL
- Utilise AES pour le chiffrement bout en bout
"""

import socket
import threading
import json
import logging
import mysql.connector
from datetime import datetime
from typing import Dict, List
import config
from encryption import AESEncryption

# Configuration du logging
logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger(__name__)


class ClientHandler(threading.Thread):
    """
    Thread gérant la communication avec un client individuel
    """
    
    def __init__(self, client_socket: socket.socket, client_address: tuple, 
                 server_instance, client_id: int):
        """
        Initialise le gestionnaire de client
        
        Args:
            client_socket: Socket de communication avec le client
            client_address: Adresse (IP, port) du client
            server_instance: Référence au serveur principal
            client_id: ID unique du client
        """
        super().__init__(daemon=True)
        self.client_socket = client_socket
        self.client_address = client_address
        self.server = server_instance
        self.client_id = client_id
        self.username = None
        self.encryption = None
        self.is_active = True
        
        logger.info(f"Client {client_id} connecté depuis {client_address}")
    
    def run(self):
        """
        Boucle principale du gestionnaire client
        """
        try:
            # Recevoir le username et la clé de chiffrement
            self._handle_authentication()
            
            # Boucle de réception des messages
            while self.is_active:
                data = self.client_socket.recv(config.MAX_BUFFER_SIZE).decode(config.ENCODING)
                
                if not data:
                    break
                
                # Parser le message JSON
                try:
                    message_dict = json.loads(data)
                    self._handle_message(message_dict)
                except json.JSONDecodeError:
                    logger.warning(f"Message JSON invalide de {self.username}")
        
        except Exception as e:
            logger.error(f"Erreur avec le client {self.username}: {e}")
        
        finally:
            self._cleanup()
    
    def _handle_authentication(self):
        """Gère l'authentification et l'échange de clé"""
        try:
            auth_data = self.client_socket.recv(config.MAX_BUFFER_SIZE).decode(config.ENCODING)
            auth_dict = json.loads(auth_data)
            
            self.username = auth_dict.get('username')
            secret_key_b64 = auth_dict.get('key')
            
            if not self.username:
                raise ValueError("Nom d'utilisateur manquant")
            
            if not secret_key_b64:
                raise ValueError("Clé de chiffrement manquante")
            
            # Créer l'instance de chiffrement avec la clé du client
            try:
                self.encryption = AESEncryption(
                    AESEncryption.key_from_b64(secret_key_b64)
                )
            except Exception as key_error:
                raise ValueError(f"Clé de chiffrement invalide: {key_error}")
            
            logger.info(f"Client authentifié: {self.username} (ID: {self.client_id})")
            
            # Enregistrer le client dans le serveur
            self.server.register_client(self.client_id, self.username, self)
            
            # Envoyer la confirmation
            response = json.dumps({
                'type': 'auth_ok',
                'message': f'Bienvenue {self.username}!'
            })
            self.client_socket.send(response.encode(config.ENCODING))
        
        except Exception as e:
            logger.error(f"Authentification échouée: {e}")
            try:
                error_response = json.dumps({
                    'type': 'auth_error',
                    'message': f'Erreur d\'authentification: {str(e)}'
                })
                self.client_socket.send(error_response.encode(config.ENCODING))
            except:
                pass
            self.is_active = False
    
    def _handle_message(self, message_dict: dict):
        """
        Traite un message reçu
        
        Args:
            message_dict: Dictionnaire contenant le message
        """
        msg_type = message_dict.get('type')
        
        if msg_type == 'message':
            self._process_message(message_dict)
        elif msg_type == 'get_history':
            self._send_history(message_dict.get('recipient'))
        elif msg_type == 'list_users':
            self._send_user_list()
        elif msg_type == 'disconnect':
            self.is_active = False
    
    def _process_message(self, message_dict: dict):
        """Traite et sauvegarde un message"""
        try:
            recipient = message_dict.get('recipient')
            encrypted_content = message_dict.get('content')

            # Décrypter le contenu pour le re-chiffrer avec la clé du destinataire
            decrypted_content = self.encryption.decrypt(encrypted_content)

            timestamp = datetime.now()
            content_sender_encrypted = encrypted_content

            # Préparer une version pour le destinataire si nous connaissons sa clé
            recipient_handler = self.server.get_client(recipient)
            if recipient_handler and recipient_handler.encryption:
                try:
                    content_recipient_encrypted = recipient_handler.encryption.encrypt(decrypted_content)
                except Exception as e:
                    logger.warning(f"Impossible de pré-chiffrer pour {recipient}: {e}")
                    content_recipient_encrypted = None
            else:
                content_recipient_encrypted = None

            # Sauvegarder en base de données (on renseigne l'IP de l'expéditeur)
            ip = self.client_address[0] if self.client_address else None
            self.server.database.save_message(
                sender=self.username,
                recipient=recipient,
                content_sender=content_sender_encrypted,
                content_recipient=content_recipient_encrypted,
                timestamp=timestamp,
                ip_sender=ip
            )

            logger.info(f"Message de {self.username} à {recipient}: {len(decrypted_content)} caractères")

            # Transmettre au destinataire si connecté
            if recipient_handler:
                try:
                    if recipient_handler.encryption:
                        encrypted_for_recipient = recipient_handler.encryption.encrypt(decrypted_content)
                    else:
                        encrypted_for_recipient = AESEncryption().encrypt(decrypted_content)

                    response = json.dumps({
                        'type': 'message',
                        'sender': self.username,
                        'content': encrypted_for_recipient,
                        'timestamp': timestamp.isoformat()
                    })
                    recipient_handler.client_socket.send(response.encode(config.ENCODING))
                except Exception as e:
                    logger.warning(f"Impossible d'envoyer le message à {recipient}: {e}")
            else:
                logger.info(f"Client {recipient} non connecté, message sauvegardé")

        except Exception as e:
            logger.error(f"Erreur de traitement de message: {e}")
    
    def _send_history(self, recipient: str):
        """Envoie l'historique des messages au client.

        Le serveur stocke toujours les deux versions possibles dans la table, mais
        il se peut que la colonne destinataire soit NULL (message envoyé quand le
        destinataire était hors ligne). Dans ce cas nous devons déchiffrer avec la
        clé de l'expéditeur (que nous conservons dans user_keys) puis re‑chiffrer
        avec la clé du demandeur avant de transmettre. Le champ timestamp est
        converti en string ISO pour rester JSON‑sérialisable.
        """
        try:
            raw_messages = self.server.database.get_messages(self.username, recipient)
            adapted = []
            for msg in raw_messages:
                # convertir timestamp pour JSON
                if isinstance(msg.get('timestamp'), datetime):
                    msg['timestamp'] = msg['timestamp'].isoformat()

                # si je suis l'expéditeur, je garde la version "content"
                if msg['sender'] == self.username:
                    msg['content'] = msg['content']
                else:
                    # je suis le destinataire
                    if msg.get('content_encrypted_for_recipient'):
                        msg['content'] = msg['content_encrypted_for_recipient']
                    else:
                        # essayer de reconstruire la version destinataire
                        try:
                            # récupérer un chiffreur pour l'expéditeur (indépendamment de sa connexion)
                            sender_cipher = self.server.get_user_encryption(msg['sender'])
                            if sender_cipher:
                                plaintext = sender_cipher.decrypt(msg['content'])
                                # chiffrer avec ma clé actuelle
                                msg['content'] = self.encryption.encrypt(plaintext)
                                # mettre à jour la base pour éviter de refaire ce travail
                                self.server.database.update_recipient_encryption(
                                    msg['message_id'], msg['content']
                                )
                            else:
                                # pas de clé connue : on laisse la version initiale (implosera en client)
                                logger.warning(f"Clef de l'expediteur {msg['sender']} indisponible")
                                msg['content'] = msg['content']
                        except Exception as e:
                            logger.warning(f"Impossible de re-chiffrer message {msg['message_id']}: {e}")
                            msg['content'] = msg['content']
                # on ne veut plus exposer la colonne interne
                msg.pop('content_encrypted_for_recipient', None)
                adapted.append(msg)

            response = json.dumps({
                'type': 'history',
                'messages': adapted,
                'count': len(adapted)
            })
            self.client_socket.send(response.encode(config.ENCODING))
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'historique: {e}")
    
    def _send_user_list(self):
        """Envoie la liste des utilisateurs connectés"""
        try:
            users = self.server.get_connected_users()
            
            response = json.dumps({
                'type': 'user_list',
                'users': users
            })
            self.client_socket.send(response.encode(config.ENCODING))
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de la liste d'utilisateurs: {e}")
    
    def _cleanup(self):
        """Nettoie les ressources à la déconnexion"""
        try:
            self.is_active = False
            self.client_socket.close()
            if self.username:
                self.server.unregister_client(self.username)
            logger.info(f"Client {self.username} déconnecté")
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage: {e}")


class ChatDatabase:
    """
    Gère les connexions à la base de données MySQL
    """
    
    def __init__(self):
        """Initialise la connexion MySQL"""
        self.connection = None
        self.connect()
    
    def connect(self):
        """Établit la connexion MySQL"""
        try:
            self.connection = mysql.connector.connect(**config.DB_CONFIG)
            logger.info("Connecté à la base de données MySQL")
        except Exception as e:
            logger.error(f"Connexion MySQL échouée: {e}")
            raise
    
    def save_message(self, sender: str, recipient: str, content_sender: str, 
                     content_recipient: str, timestamp: datetime, ip_sender: str = None):
        """
        Sauvegarde un message en base de données avec deux versions chiffrées
        
        Args:
            sender: Nom d'utilisateur de l'expéditeur
            recipient: Nom d'utilisateur du destinataire
            content_sender: Contenu chiffré avec la clé de l'expéditeur
            content_recipient: Contenu chiffré avec la clé du destinataire (peut être None)
            timestamp: Date/heure du message
            ip_sender: Adresse IP de l'expéditeur (optionnel)
        """
        try:
            cursor = self.connection.cursor()
            query = """
                INSERT INTO messages (sender, recipient, content, content_encrypted_for_recipient, timestamp, is_read, ip_sender)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (sender, recipient, content_sender, content_recipient, timestamp, False, ip_sender))
            self.connection.commit()
            cursor.close()
            logger.debug(f"Message sauvegardé en BD: {sender} -> {recipient}")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde du message: {e}")
    
    def get_messages(self, requesting_user: str, other_user: str, limit: int = 100) -> list:
        """
        Récupère l'historique des messages entre deux utilisateurs.

        Contrairement à la version précédente, cette méthode retourne les données
        brutes (colonnes "content" et "content_encrypted_for_recipient") afin
        que le handler client puisse les adapter et, si nécessaire, ré‑chiffrer
        dynamiquement. La conversion de timestamp en chaîne est gérée plus haut.
        """
        try:
            cursor = self.connection.cursor(dictionary=True)
            query = """
                SELECT message_id, sender, recipient, content, content_encrypted_for_recipient, 
                       timestamp, is_read, ip_sender
                FROM messages
                WHERE (sender = %s AND recipient = %s) OR (sender = %s AND recipient = %s)
                ORDER BY timestamp ASC
                LIMIT %s
            """
            cursor.execute(query, (requesting_user, other_user, other_user, requesting_user, limit))
            messages = cursor.fetchall()
            cursor.close()
            return messages
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des messages: {e}")
            return []
    
    def update_recipient_encryption(self, message_id: int, content_recipient: str):
        """Met à jour la colonne content_encrypted_for_recipient pour un message"""
        try:
            cursor = self.connection.cursor()
            query = """UPDATE messages
                       SET content_encrypted_for_recipient = %s
                       WHERE message_id = %s"""
            cursor.execute(query, (content_recipient, message_id))
            self.connection.commit()
            cursor.close()
            logger.debug(f"content_encrypted_for_recipient mis à jour pour message {message_id}")
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour du chiffrement destinataire: {e}")

    def close(self):
        """Ferme la connexion MySQL"""
        if self.connection:
            self.connection.close()
            logger.info("Connexion MySQL fermée")


class ChatServer:
    """
    Serveur de chat multi-client principal
    """
    
    def __init__(self, host: str = config.SERVER_HOST, port: int = config.SERVER_PORT):
        """
        Initialise le serveur
        
        Args:
            host: Adresse IP d'écoute
            port: Port d'écoute
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients: Dict[str, ClientHandler] = {}  # {username: ClientHandler}
        # stocke également les clés de chiffrement connues pour chaque utilisateur afin de pouvoir
        # déchiffrer des messages même quand l'utilisateur est déconnecté
        self.user_keys: Dict[str, bytes] = {}  # {username: shared_key_bytes}
        self.client_threads: Dict[int, ClientHandler] = {}  # {client_id: ClientHandler}
        self.client_counter = 0
        self.lock = threading.Lock()
        self.database = ChatDatabase()
        self.is_running = False
    
    def start(self):
        """Lance le serveur"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.is_running = True
            
            logger.info(f"Serveur démarré sur {self.host}:{self.port}")
            
            # Accepter les connexions
            while self.is_running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    with self.lock:
                        self.client_counter += 1
                        client_id = self.client_counter
                    
                    # Créer et démarrer un thread pour ce client
                    handler = ClientHandler(client_socket, client_address, self, client_id)
                    self.client_threads[client_id] = handler
                    handler.start()
                
                except KeyboardInterrupt:
                    logger.info("Arrêt du serveur...")
                    self.stop()
                except Exception as e:
                    logger.error(f"Erreur lors de l'acceptation de connexion: {e}")
        
        except Exception as e:
            logger.error(f"Erreur du serveur: {e}")
        
        finally:
            self.stop()
    
    def register_client(self, client_id: int, username: str, handler: ClientHandler):
        """Enregistre un client connecté et conserve sa clé"""
        with self.lock:
            self.clients[username] = handler
            # conserver la clé dans le cache même si le handler partira plus tard
            if handler.encryption:
                self.user_keys[username] = handler.encryption.key
            logger.info(f"Client enregistré: {username}")
    
    def unregister_client(self, username: str):
        """Désenregistre un client mais conserve la clé dans le cache"""
        with self.lock:
            if username in self.clients:
                del self.clients[username]
                logger.info(f"Client désenregistré: {username}")
            # ne pas supprimer user_keys : cette clé pourra servir pour chiffrer ultérieurement
    
    def get_client(self, username: str) -> ClientHandler:
        """Récupère un gestionnaire de client par username"""
        with self.lock:
            return self.clients.get(username)

    def get_user_encryption(self, username: str):
        """Retourne un objet AESEncryption pour un utilisateur connu.

        Si l'utilisateur est connecté, on récupère directement son handler,
        sinon on reconstruit l'instance à partir de la clé stockée en cache.
        """
        with self.lock:
            handler = self.clients.get(username)
            if handler and handler.encryption:
                return handler.encryption
            key = self.user_keys.get(username)
            if key:
                return AESEncryption(key)
        return None
    
    def get_connected_users(self) -> list:
        """Retourne la liste des utilisateurs connectés"""
        with self.lock:
            return list(self.clients.keys())
    
    def stop(self):
        """Arrête le serveur"""
        self.is_running = False
        
        # Fermer tous les clients
        with self.lock:
            for client_handler in self.clients.values():
                try:
                    client_handler.client_socket.close()
                except:
                    pass
            self.clients.clear()
        
        # Fermer la base de données
        self.database.close()
        
        # Fermer le socket serveur
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        logger.info("Serveur arrêté")


def main():
    """Point d'entrée du serveur"""
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Arrêt interrompu démarré...")
        server.stop()


if __name__ == "__main__":
    main()
