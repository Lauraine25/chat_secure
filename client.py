"""
Client de messagerie avec interface Tkinter
- Interface graphique pour l'envoi/réception de messages
- Chiffrement bout en bout avec AES
- Connexion TCP au serveur
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import json
import threading
import logging
import string
import random
from datetime import datetime
from typing import Optional
import config
from encryption import AESEncryption

# Configuration du logging
logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger(__name__)


class ChatClient:
    """
    Client de messagerie avec interface Tkinter
    """
    
    def __init__(self, root: tk.Tk):
        """
        Initialise le client
        
        Args:
            root: Fenêtre Tkinter principale
        """
        self.root = root
        self.root.title("Chat Sécurisé - Client")
        self.root.geometry("800x600")
        
        # Variables d'état
        self.socket = None
        self.username = None
        self.encryption = None
        self.passphrase_salt = None  # Sel stocké pour PBKDF2
        self.is_connected = False
        self.receive_thread = None
        
        # Variables Tkinter
        self.status_var = tk.StringVar(value="Non connecté")
        self.users_var = tk.StringVar()
        
        # Construire l'interface
        self._build_ui()
        
        # Gérer la fermeture
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    
    def _build_ui(self):
        """Construit l'interface utilisateur"""
        
        # Frame principal pour les passphrases (DÉBUT - étape obligatoire)
        passphrase_section = ttk.LabelFrame(self.root, text="Étape 1: Sécurisation", padding=15)
        passphrase_section.pack(fill="x", padx=10, pady=5)
        
        # Instructions claires
        instructions = ttk.Label(
            passphrase_section,
            text="Avant d'accéder à la messagerie, créez une passphrase pour chiffrer vos messages.\n(Utilisez au minimum 8 caractères)",
            justify="center",
            wraplength=700
        )
        instructions.pack(pady=(0, 10))
        
        # Frame pour les champs de passphrase
        pass_frame = ttk.Frame(passphrase_section)
        pass_frame.pack(fill="x", pady=10)
        
        ttk.Label(pass_frame, text="Passphrase:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.passphrase_entry1 = ttk.Entry(pass_frame, width=40, show="•")
        self.passphrase_entry1.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(pass_frame, text="Confirmation:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.passphrase_entry2 = ttk.Entry(pass_frame, width=40, show="•")
        self.passphrase_entry2.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        pass_frame.columnconfigure(1, weight=1)
        
        # Boutons pour les passphrases
        button_frame_pass = ttk.Frame(passphrase_section)
        button_frame_pass.pack(fill="x", pady=10)
        
        self.set_passphrase_btn = ttk.Button(
            button_frame_pass,
            text="Valider la passphrase",
            command=self._validate_and_set_passphrase
        )
        self.set_passphrase_btn.pack(side="left", padx=5)
        
        generate_btn = ttk.Button(
            button_frame_pass,
            text="Générer aléatoirement",
            command=self._generate_random_passphrase
        )
        generate_btn.pack(side="left", padx=5)
        
        # Indicateur d'état de la passphrase
        self.passphrase_status_var = tk.StringVar(value="Passphrase non définie")
        self.passphrase_status_label = ttk.Label(
            passphrase_section,
            textvariable=self.passphrase_status_var,
            foreground="red",
            font=("Arial", 10, "bold")
        )
        self.passphrase_status_label.pack(pady=5)
        
        # SÉPARATEUR
        ttk.Separator(self.root, orient="horizontal").pack(fill="x", padx=10, pady=5)
        
        # Frame de connexion au serveur (ÉTAPE 2 - déverrouillée après passphrase)
        connection_frame = ttk.LabelFrame(self.root, text="Étape 2: Accès à la Messagerie", padding=10)
        connection_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(connection_frame, text="Serveur:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.server_entry = ttk.Entry(connection_frame, width=30)
        self.server_entry.insert(0, config.SERVER_HOST)
        self.server_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.port_entry = ttk.Entry(connection_frame, width=10)
        self.port_entry.insert(0, str(config.SERVER_PORT))
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(connection_frame, text="Nom d'utilisateur:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.username_entry = ttk.Entry(connection_frame, width=30)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        
        self.connect_button = ttk.Button(
            connection_frame, text="Accéder à la Messagerie", 
            command=self._connect_to_server, state="disabled"
        )
        self.connect_button.grid(row=1, column=2, columnspan=2, padx=5, pady=5, sticky="ew")

        ttk.Label(connection_frame, text="Nouvelle Passphrase:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.new_passphrase_entry = ttk.Entry(connection_frame, width=30, show="•")
        self.new_passphrase_entry.grid(row=2, column=1, padx=5, pady=5)
        
        self.change_passphrase_button = ttk.Button(
            connection_frame, text="Changer", 
            command=self._change_passphrase, state="disabled"
        )
        self.change_passphrase_button.grid(row=2, column=2, columnspan=2, padx=5, pady=5, sticky="ew")
        
        # Status bar
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(status_frame, text="État:").pack(side="left", padx=5)
        ttk.Label(status_frame, textvariable=self.status_var, foreground="blue").pack(side="left", padx=5)
        
        # Main content avec PanedWindow
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Panel gauche: Liste des utilisateurs
        left_frame = ttk.LabelFrame(paned, text="Utilisateurs Connectés", padding=5)
        paned.add(left_frame, weight=1)
        
        scrollbar = ttk.Scrollbar(left_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.users_listbox = tk.Listbox(left_frame, yscrollcommand=scrollbar.set)
        self.users_listbox.pack(fill="both", expand=True)
        scrollbar.config(command=self.users_listbox.yview)
        
        refresh_button = ttk.Button(left_frame, text="Rafraîchir", command=self._refresh_users)
        refresh_button.pack(fill="x", padx=5, pady=5)
        
        # Panel droit: Chat
        right_frame = ttk.LabelFrame(paned, text="Messages", padding=5)
        paned.add(right_frame, weight=2)
        
        # Layout par grille dans right_frame pour garder les contrôles visibles
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)  # zone messages
        
        # Zone d'affichage des messages (ligne 0)
        self.messages_text = scrolledtext.ScrolledText(
            right_frame, wrap="word", height=15, state="disabled"
        )
        self.messages_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Configuration des tags pour le formatage
        self.messages_text.tag_config("sender", foreground="blue", font=("Arial", 10, "bold"))
        self.messages_text.tag_config("timestamp", foreground="gray", font=("Arial", 8, "italic"))
        self.messages_text.tag_config("message", font=("Arial", 10))
        
        # Ligne destinataire (ligne 1)
        compose_frame = ttk.Frame(right_frame)
        compose_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=(5,0))
        compose_frame.columnconfigure(1, weight=1)
        ttk.Label(compose_frame, text="À:").grid(row=0, column=0, padx=5)
        self.recipient_var = tk.StringVar()
        self.recipient_combo = ttk.Combobox(compose_frame, textvariable=self.recipient_var, width=20)
        self.recipient_combo.grid(row=0, column=1, padx=5, sticky="ew")
        # lorsque l'utilisateur choisit un destinataire, charger automatiquement l'historique
        self.recipient_combo.bind("<<ComboboxSelected>>", lambda e: self._load_history())
        
        # Ligne saisie message (ligne 2)
        ttk.Label(right_frame, text="Message:").grid(row=2, column=0, sticky="w", padx=5, pady=(5,0))
        self.message_text = tk.Text(right_frame, height=4, wrap="word")
        self.message_text.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)
        right_frame.rowconfigure(3, weight=0)
        
        # Ligne boutons (ligne 4)
        button_frame = ttk.Frame(right_frame)
        button_frame.grid(row=4, column=0, sticky="ew", padx=5, pady=5)
        
        self.send_button = ttk.Button(
            button_frame, text="Envoyer", 
            command=self._send_message, state="disabled"
        )
        self.send_button.pack(side="left", padx=5)
        
        self.history_button = ttk.Button(
            button_frame, text="Charger l'historique", 
            command=self._load_history, state="disabled"
        )
        self.history_button.pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Effacer", command=self._clear_messages).pack(side="left", padx=5)
        
        # Focus sur le premier champ de passphrase
        self.passphrase_entry1.focus()
    
    def _validate_and_set_passphrase(self):
        """Valide et définit la passphrase"""
        pass1 = self.passphrase_entry1.get()
        pass2 = self.passphrase_entry2.get()
        
        if not pass1:
            messagebox.showerror("Erreur", "La passphrase ne peut pas être vide.")
            return
        
        if pass1 != pass2:
            messagebox.showerror("Erreur", "Les passphrases ne correspondent pas.")
            return
        
        if len(pass1) < 8:
            messagebox.showwarning("Avertissement", "Il est recommandé d'utiliser au moins 8 caractères.")
        
        # Dériver la clé avec PBKDF2
        try:
            key_bytes, self.passphrase_salt = AESEncryption.key_from_password(pass1)
            self.encryption = AESEncryption(key_bytes)
            
            # Mettre à jour l'interface
            self.passphrase_status_var.set("Passphrase validée - Prêt à se connecter!")
            self.passphrase_status_label.config(foreground="green")
            
            # Activer les contrôles de connexion
            self.connect_button.config(state="normal")
            self.change_passphrase_button.config(state="normal")
            
            # Nettoyer les champs de passphrase
            self.passphrase_entry1.delete(0, tk.END)
            self.passphrase_entry2.delete(0, tk.END)
            self.set_passphrase_btn.config(state="disabled")
            
            logger.info("Passphrase acceptée et clé dérivée")
            messagebox.showinfo("Succès", "Passphrase validée! Vous pouvez maintenant accéder à la messagerie.")
        
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la dérivation de clé: {e}")
            logger.error(f"Erreur validation passphrase: {e}")
    
    def _generate_random_passphrase(self):
        """Génère une passphrase aléatoire sécurisée"""
        # Générer une passphrase aléatoire de 16 caractères
        chars = string.ascii_letters + string.digits + "!@#$%&"
        random_pass = ''.join(random.choice(chars) for _ in range(16))
        
        # Remplir les deux champs
        self.passphrase_entry1.delete(0, tk.END)
        self.passphrase_entry1.insert(0, random_pass)
        self.passphrase_entry2.delete(0, tk.END)
        self.passphrase_entry2.insert(0, random_pass)
        
        # Valider automatiquement
        self._validate_and_set_passphrase()
        
        # Afficher la passphrase dans une boîte de dialogue
        messagebox.showinfo(
            "Passphrase générée",
            f"Passphrase générée et validée:\n\n{random_pass}\n\n(Conservez la pour vos connexions futures)"
        )
    
    def _connect_to_server(self):
        """Établit la connexion avec le serveur"""
        try:
            server = self.server_entry.get().strip()
            port = int(self.port_entry.get().strip())
            self.username = self.username_entry.get().strip()

            if not self.username:
                messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur")
                return

            # Vérifier que la passphrase a été définie
            if self.encryption is None:
                messagebox.showerror("Erreur", "Veuillez d'abord valider une passphrase (Étape 1)")
                return

            # Créer le socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((server, port))

            # Envoyer l'authentification avec clé et sel
            auth_data = json.dumps({
                'username': self.username,
                'key': self.encryption.get_key_b64(),
                'salt': AESEncryption.salt_to_b64(self.passphrase_salt)
            })
            self.socket.send(auth_data.encode(config.ENCODING))
            
            # Attendre la confirmation
            response = self.socket.recv(config.MAX_BUFFER_SIZE).decode(config.ENCODING)
            response_dict = json.loads(response)
            
            if response_dict.get('type') == 'auth_ok':
                self.is_connected = True
                self.status_var.set(f"Connecté en tant que {self.username}")
                
                # Désactiver la zone de connexion
                self.connect_button.config(state="disabled")
                self.server_entry.config(state="disabled")
                self.port_entry.config(state="disabled")
                self.username_entry.config(state="disabled")
                
                # Activer les contrôles de chat
                self.send_button.config(state="normal")
                self.history_button.config(state="normal")
                
                # Démarrer le thread de réception
                self.receive_thread = threading.Thread(target=self._receive_messages, daemon=True)
                self.receive_thread.start()
                
                # Charger la liste des utilisateurs
                self._refresh_users()
                
                messagebox.showinfo("Succès", f"Connecté en tant que {self.username}")
                logger.info(f"Connecté au serveur en tant que {self.username}")
            elif response_dict.get('type') == 'auth_error':
                error_msg = response_dict.get('message', 'Authentification échouée')
                messagebox.showerror("Erreur d'authentification", error_msg)
                logger.error(f"Erreur d'authentification: {error_msg}")
                if self.socket:
                    self.socket.close()
                    self.socket = None
            else:
                messagebox.showerror("Erreur", "Réponse du serveur invalide")
                if self.socket:
                    self.socket.close()
                    self.socket = None
        
        except Exception as e:
            messagebox.showerror("Erreur de connexion", f"Impossible de se connecter: {e}")
            logger.error(f"Erreur de connexion: {e}")
    
    def _change_passphrase(self):
        """Change la passphrase et régénère la clé de chiffrement"""
        try:
            new_passphrase = self.new_passphrase_entry.get()
            
            if not new_passphrase:
                messagebox.showerror("Erreur", "La nouvelle passphrase ne peut pas être vide")
                return
            
            if len(new_passphrase) < 8:
                messagebox.showwarning("Avertissement", "Il est recommandé d'utiliser au moins 8 caractères.")
            
            # Demander la confirmation
            result = messagebox.askyesno(
                "Confirmation",
                "Êtes-vous sûr de vouloir changer la passphrase?\nCette action régénérera votre clé de chiffrement."
            )
            
            if not result:
                return
            
            # Régénérer la clé avec la nouvelle passphrase
            try:
                key_bytes, self.passphrase_salt = AESEncryption.key_from_password(new_passphrase)
                self.encryption = AESEncryption(key_bytes)
                self.new_passphrase_entry.delete(0, tk.END)
                messagebox.showinfo("Succès", "Passphrase changée et clé régénérée avec succès!")
                logger.info("Passphrase changée et clé régénérée")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de la dérivation de clé: {e}")
                logger.error(f"Erreur lors du changement de passphrase: {e}")
        
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de changer la passphrase: {e}")
            logger.error(f"Erreur lors du changement de passphrase: {e}")
    
    def _send_message(self):
        """Envoie un message chiffré"""
        try:
            recipient = self.recipient_var.get().strip()
            message_content = self.message_text.get("1.0", "end-1c").strip()
            
            if not recipient:
                messagebox.showerror("Erreur", "Veuillez sélectionner un destinataire")
                return
            
            if not message_content:
                messagebox.showerror("Erreur", "Veuillez entrer un message")
                return
            
            # Chiffrer le message
            encrypted_content = self.encryption.encrypt(message_content)
            
            # Créer le paquet JSON
            message_dict = {
                'type': 'message',
                'recipient': recipient,
                'content': encrypted_content
            }
            
            # Envoyer
            self.socket.send(json.dumps(message_dict).encode(config.ENCODING))
            
            # Afficher le message dans la zone de chat
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.messages_text.config(state="normal")
            self.messages_text.insert("end", f"[{timestamp}] ", "timestamp")
            self.messages_text.insert("end", f"{self.username}\n", "sender")
            self.messages_text.insert("end", f"{message_content}\n\n", "message")
            self.messages_text.config(state="disabled")
            self.messages_text.see("end")
            
            # Effacer le champ de texte
            self.message_text.delete("1.0", "end")
            
            logger.info(f"Message envoyé à {recipient}")
        
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'envoyer le message: {e}")
            logger.error(f"Erreur d'envoi: {e}")
    
    def _receive_messages(self):
        """Thread de réception des messages"""
        while self.is_connected:
            try:
                data = self.socket.recv(config.MAX_BUFFER_SIZE).decode(config.ENCODING)
                
                if not data:
                    break
                
                message_dict = json.loads(data)
                msg_type = message_dict.get('type')
                
                if msg_type == 'message':
                    self._display_received_message(message_dict)
                elif msg_type == 'history':
                    self._display_history(message_dict)
                elif msg_type == 'user_list':
                    self._update_user_list(message_dict)
            
            except Exception as e:
                if self.is_connected:
                    logger.error(f"Erreur de réception: {e}")
                    break
        
        self._disconnect()
    
    def _display_received_message(self, message_dict: dict):
        """Affiche un message reçu"""
        try:
            sender = message_dict.get('sender')
            encrypted_content = message_dict.get('content')
            timestamp = message_dict.get('timestamp', '')
            
            # Déchiffrer
            decrypted_content = self.encryption.decrypt(encrypted_content)
            
            # Afficher
            self.messages_text.config(state="normal")
            if timestamp:
                self.messages_text.insert("end", f"[{timestamp[:19]}] ", "timestamp")
            else:
                self.messages_text.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] ", "timestamp")
            
            self.messages_text.insert("end", f"{sender}\n", "sender")
            self.messages_text.insert("end", f"{decrypted_content}\n\n", "message")
            self.messages_text.config(state="disabled")
            self.messages_text.see("end")
            
            logger.info(f"Message reçu de {sender}")
        
        except Exception as e:
            logger.error(f"Erreur lors de l'affichage du message: {e}")
    
    def _display_history(self, history_dict: dict):
        """Affiche l'historique des messages"""
        try:
            self._clear_messages()
            messages = history_dict.get('messages', [])
            
            self.messages_text.config(state="normal")
            if not messages:
                self.messages_text.insert("end", "Aucun historique disponible\n")
            else:
                # afficher un en-tête indiquant le nombre de messages
                self.messages_text.insert("end", f"--- Historique ({len(messages)} messages) ---\n")
                for msg in messages:
                    timestamp = msg.get('timestamp', '')
                    sender = msg.get('sender', '')
                    content = msg.get('content', '')
                    
                    # Le serveur renvoie le contenu déjà chiffré avec notre clé
                    # (clé d'expéditeur si nous avons envoyé, clé de destinataire si reçu)
                    try:
                        decrypted_content = self.encryption.decrypt(content)
                    except Exception as decrypt_error:
                        logger.warning(f"Impossible de déchiffrer le message: {decrypt_error}")
                        decrypted_content = f"[ERREUR DÉCHIFFREMENT: {str(decrypt_error)}]"
                    
                    if timestamp:
                        self.messages_text.insert("end", f"[{timestamp[:19]}] ", "timestamp")
                    self.messages_text.insert("end", f"{sender}\n", "sender")
                    self.messages_text.insert("end", f"{decrypted_content}\n\n", "message")
            
            self.messages_text.config(state="disabled")
            self.messages_text.see("end")
        
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de charger l'historique: {e}")
            logger.error(f"Erreur d'historique: {e}")
    
    def _update_user_list(self, users_dict: dict):
        """Met à jour la liste des utilisateurs"""
        try:
            users = users_dict.get('users', [])
            # Filtrer le propre nom d'utilisateur
            users = [u for u in users if u != self.username]
            
            self.users_listbox.delete(0, "end")
            for user in sorted(users):
                self.users_listbox.insert("end", user)
            
            # Mettre à jour la combo box
            self.recipient_combo['values'] = sorted(users)
        
        except Exception as e:
            logger.error(f"Erreur de mise à jour de la liste: {e}")
    
    def _refresh_users(self):
        """Demande la liste des utilisateurs connectés"""
        if self.is_connected:
            try:
                request = json.dumps({'type': 'list_users'})
                self.socket.send(request.encode(config.ENCODING))
            except Exception as e:
                logger.error(f"Erreur de rafraîchissement: {e}")
    
    def _load_history(self):
        """Charge l'historique avec le destinataire sélectionné"""
        try:
            recipient = self.recipient_var.get().strip()
            if not recipient:
                messagebox.showerror("Erreur", "Veuillez sélectionner un utilisateur")
                return
            
            request = json.dumps({
                'type': 'get_history',
                'recipient': recipient
            })
            logger.debug(f"Envoi requête historique vers {recipient}")
            self.socket.send(request.encode(config.ENCODING))
        
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de charger l'historique: {e}")
            logger.error(f"Erreur: {e}")
    
    def _clear_messages(self):
        """Efface la zone de messages"""
        self.messages_text.config(state="normal")
        self.messages_text.delete("1.0", "end")
        self.messages_text.config(state="disabled")
    
    def _disconnect(self):
        """Déconnecte le client"""
        self.is_connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.status_var.set("Déconnecté")
        self.connect_button.config(state="normal")
        self.server_entry.config(state="normal")
        self.port_entry.config(state="normal")
        self.username_entry.config(state="normal")
        self.send_button.config(state="disabled")
        self.history_button.config(state="disabled")
        
        logger.info("Déconnecté du serveur")
    
    def _on_closing(self):
        """Gère la fermeture de l'application"""
        if self.is_connected:
            try:
                disconnect_msg = json.dumps({'type': 'disconnect'})
                self.socket.send(disconnect_msg.encode(config.ENCODING))
            except:
                pass
            self._disconnect()
        # effacer la passphrase de la zone de saisie afin qu'elle ne traine pas en mémoire
        try:
            self.password_entry.delete(0, 'end')
        except Exception:
            pass
        self.root.destroy()


def main():
    """Point d'entrée du client"""
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()


if __name__ == "__main__":
    main()
