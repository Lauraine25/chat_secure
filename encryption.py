"""
Module de chiffrement AES pour les communications sécurisées
Utilise AES-256-CBC avec authentification HMAC-SHA256 (AEAD)
"""

import os
import base64
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import config

logger = logging.getLogger(__name__)


class AESEncryption:
    """
    Classe pour gérer le chiffrement/déchiffrement AES-256-CBC
    """
    
    def __init__(self, shared_key: bytes = None):
        """
        Initialise le gestionnaire de chiffrement
        
        Args:
            shared_key: Clé partagée de 32 bytes (256 bits)
                       Si None, génère une nouvelle clé
        """
        if shared_key is None:
            self.key = self.generate_key()
        else:
            if len(shared_key) != 32:
                raise ValueError(f"La clé doit faire 32 bytes, reçu {len(shared_key)}")
            self.key = shared_key
        
        self.backend = default_backend()
    
    @staticmethod
    def generate_key() -> bytes:
        """
        Génère une clé aléatoire de 256 bits (32 bytes)
        
        Returns:
            bytes: Clé aléatoire pour AES-256
        """
        key = os.urandom(32)
        logger.info("Nouvelle clé de chiffrement générée")
        return key
    
    @staticmethod
    def generate_iv() -> bytes:
        """
        Génère un vecteur d'initialisation (IV) aléatoire
        
        Returns:
            bytes: IV de 16 bytes pour CBC mode
        """
        return os.urandom(16)
    
    def _compute_hmac(self, data: bytes) -> bytes:
        """
        Calcule une signature HMAC-SHA256 pour les données.
        
        Args:
            data: Les données à signer (bytes)
            
        Returns:
            bytes: Signature HMAC-SHA256 (32 bytes)
        """
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=self.backend)
        h.update(data)
        return h.finalize()
    
    def _verify_hmac(self, data: bytes, signature: bytes) -> bool:
        """
        Vérifie une signature HMAC-SHA256.
        
        Args:
            data: Les données à vérifier (bytes)
            signature: La signature attendue (bytes)
            
        Returns:
            bool: True si valide, False sinon
        """
        try:
            h = hmac.HMAC(self.key, hashes.SHA256(), backend=self.backend)
            h.update(data)
            h.verify(signature)
            return True
        except Exception as e:
            logger.warning(f"Vérification HMAC échouée: {e}")
            return False
    
    def encrypt(self, plaintext: str) -> str:
        """
        Chiffre un texte en clair
        
        Args:
            plaintext: Texte à chiffrer
            
        Returns:
            str: Texte chiffré encodé en base64 (IV + ciphertext)
        """
        try:
            # Convertir le texte en bytes
            plaintext_bytes = plaintext.encode(config.ENCODING)
            
            # Générer un IV aléatoire
            iv = self.generate_iv()
            
            # Appliquer le padding PKCS7
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext_bytes) + padder.finalize()
            
            # Créer la suite de chiffrement AES-256-CBC
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Chiffrer les données
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combiner IV + ciphertext et encoder en base64
            encrypted_data = iv + ciphertext
            encrypted_b64 = base64.b64encode(encrypted_data).decode('ascii')
            
            # Calculer la signature HMAC du ciphertext (authentication)
            hmac_signature = self._compute_hmac(encrypted_data)
            hmac_b64 = base64.b64encode(hmac_signature).decode('ascii')
            
            # Format final : ciphertext:hmac_signature (séparés par ':')
            result = f"{encrypted_b64}:{hmac_b64}"
            
            logger.debug(f"Texte chiffré + HMAC: {len(plaintext_bytes)} bytes -> {len(result)} chars (avec HMAC)")
            return result
            
        except Exception as e:
            logger.error(f"Erreur de chiffrement: {e}")
            raise
    
    def decrypt(self, message_with_hmac: str) -> str:
        """
        Déchiffre et vérifie un texte chiffré avec authentification HMAC.
        
        Args:
            message_with_hmac: Message au format "ciphertext_b64:hmac_b64"
            
        Returns:
            str: Texte déchiffré
            
        Raises:
            ValueError: Si la signature HMAC n'est pas valide
        """
        try:
            # Séparer le ciphertext et la signature HMAC
            if ':' not in message_with_hmac:
                raise ValueError("Format invalide: le message doit contenir ciphertext:hmac")
            
            encrypted_b64, hmac_b64 = message_with_hmac.rsplit(':', 1)
            
            # Décoder depuis base64
            encrypted_data = base64.b64decode(encrypted_b64.encode('ascii'))
            hmac_signature = base64.b64decode(hmac_b64.encode('ascii'))
            
            # Vérifier la signature HMAC AVANT de déchiffrer (important!)
            if not self._verify_hmac(encrypted_data, hmac_signature):
                raise ValueError("Authentification HMAC échouée: le message a été modifié ou la clé est incorrecte")
            
            # Vérifier la longueur minimale (IV + au moins 1 bloc)
            if len(encrypted_data) < 32:
                raise ValueError(f"Données chiffrées trop courtes: {len(encrypted_data)} bytes (min 32)")
            
            # Extraire IV (16 premiers bytes) et ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            logger.debug(f"Déchiffrement vérifié: IV={len(iv)} bytes, ciphertext={len(ciphertext)} bytes")
            
            # Créer la suite de déchiffrement
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Déchiffrer les données
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Retirer le padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Convertir en string
            plaintext = plaintext_bytes.decode(config.ENCODING)
            
            logger.debug(f"Texte déchiffré avec succès (HMAC vérifié): {len(ciphertext)} bytes -> {len(plaintext)} chars")
            return plaintext
            
        except Exception as e:
            logger.error(f"Erreur de déchiffrement (données corrompues ou mauvaise clé): {e}")
            logger.debug(f"Longueur données b64: {len(ciphertext_b64)}, décodées: {len(encrypted_data) if 'encrypted_data' in locals() else 'N/A'}")
            raise
    
    def get_key_b64(self) -> str:
        """
        Retourne la clé encodée en base64 (utile pour transmission)
        
        Returns:
            str: Clé encodée en base64
        """
        return base64.b64encode(self.key).decode('ascii')
    
    @staticmethod
    def key_from_b64(key_b64: str) -> bytes:
        """
        Decode une clé depuis base64
        
        Args:
            key_b64: Clé encodée en base64
            
        Returns:
            bytes: Clé décodée
        """
        return base64.b64decode(key_b64.encode('ascii'))

    @staticmethod
    def key_from_password(passphrase: str, salt: bytes = None) -> tuple:
        """
        Dérive une clé AES-256 à partir d'une passphrase using PBKDF2-HMAC-SHA256.

        Utilise:
        - PBKDF2 avec HMAC-SHA256
        - 480 000 itérations (conforme OWASP 2024)
        - Un sel aléatoire de 16 bytes si non fourni

        Args:
            passphrase: Phrase de passe fournie par l'utilisateur
            salt: Sel binaire (16 bytes). Si None, généré aléatoirement.

        Returns:
            tuple: (clé_32_bytes, sel_16_bytes)
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode(config.ENCODING))
        logger.info(f"Clé dérivée avec PBKDF2-HMAC (salt={base64.b64encode(salt).decode('ascii')[:16]}...)")
        return (key, salt)

    @staticmethod
    def salt_to_b64(salt: bytes) -> str:
        """Encode un sel en base64 pour transmission"""
        return base64.b64encode(salt).decode('ascii')

    @staticmethod
    def salt_from_b64(salt_b64: str) -> bytes:
        """Décode un sel depuis base64"""
        return base64.b64decode(salt_b64.encode('ascii'))


# Exemple d'utilisation
if __name__ == "__main__":
    # Créer une instance de chiffrement
    cipher = AESEncryption()
    
    # Texte à chiffrer
    original = "Ceci est un message secret!"
    
    # Chiffrer
    encrypted = cipher.encrypt(original)
    print(f"Message original: {original}")
    print(f"Message chiffré: {encrypted}")
    
    # Déchiffrer
    decrypted = cipher.decrypt(encrypted)
    print(f"Message déchiffré: {decrypted}")
    
    # Vérifier que c'est identique
    assert original == decrypted, "Chiffrement/déchiffrement échoué!"
    print("✓ Chiffrement/déchiffrement réussi!")
