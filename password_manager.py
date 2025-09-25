#!/usr/bin/env python3
"""
Gestor de Contraseñas Seguro
Universidad Católica Boliviana "San Pablo"
MIS-707 - Fundamentos de Ciberseguridad

Este programa implementa un gestor de contraseñas seguro utilizando:
- Cifrado simétrico AES-256-GCM
- Derivación de claves con PBKDF2
- Almacenamiento seguro en archivos encriptados
- Hash SHA-256 para verificación de integridad
"""

import os
import json
import base64
import hashlib
import getpass
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SecurePasswordManager:
        # --- CONSTANTES ---
    SALT_LENGTH = 16 # bytes
    IV_LENGTH = 12   # bytes (AES GCM recomienda 96 bits = 12 bytes)
    TAG_LENGTH = 16  # bytes (AES GCM tag es de 128 bits = 16 bytes)
    PBKDF2_ITERATIONS = 100000
    KEY_LENGTH = 32 # bytes (AES-256 = 32 bytes)
    MIN_MASTER_PASSWORD_LENGTH = 8
    

    def __init__(self, database_file="passwords.enc"):
        self.database_file = database_file
        self.master_key = None
        self.backend = default_backend()
        
    def derive_key(self, password, salt):
        """Deriva una clave de cifrado usando PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,  # 256 bits
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def generate_salt(self):
        """Genera un salt aleatorio de 16 bytes"""
        return os.urandom(self.SALT_LENGTH)
    
    def encrypt_data(self, data, key):
        """Cifra los datos usando AES-256-GCM"""
        # Generar IV aleatorio
        iv = os.urandom(self.IV_LENGTH)  # 96 bits para GCM
        
        # Crear cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Cifrar datos
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        
        # Retornar IV + tag + ciphertext codificado en base64
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()
    
    def decrypt_data(self, encrypted_data, key):
        """Descifra los datos usando AES-256-GCM"""
        try:
            # Decodificar de base64
            data = base64.b64decode(encrypted_data)
            
            # Extraer IV, tag y ciphertext
            iv = data[:self.IV_LENGTH]
            tag = data[self.IV_LENGTH : self.IV_LENGTH + self.TAG_LENGTH]
            ciphertext = data[self.IV_LENGTH + self.TAG_LENGTH :]
            
            # Crear cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Descifrar
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode()
        except Exception as e:
            raise ValueError("Error al descifrar los datos: clave incorrecta o datos corruptos")
    
    def hash_password(self, password):
        """Genera un hash SHA-256 de la contraseña"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate(self):
        """Autentica al usuario con la contraseña maestra"""
        if os.path.exists(self.database_file):
            master_password = getpass.getpass("Ingrese la contraseña maestra: ")
            try:
                self.load_database(master_password)
                print("✓ Autenticación exitosa")
                return True
            except:
                print("✗ Contraseña maestra incorrecta")
                return False
        else:
            print("Configuración inicial del gestor de contraseñas")
            master_password = getpass.getpass("Cree una contraseña maestra: ")
            confirm_password = getpass.getpass("Confirme la contraseña maestra: ")
            
            if master_password != confirm_password:
                print("✗ Las contraseñas no coinciden")
                return False
            
            if len(master_password) < self.MIN_MASTER_PASSWORD_LENGTH:
                print("✗ La contraseña maestra debe tener al menos 8 caracteres")
                return False
                
            # Crear nueva base de datos
            salt = self.generate_salt()
            self.master_key = self.derive_key(master_password, salt)
            self.save_database({}, salt)
            print("✓ Gestor de contraseñas configurado exitosamente")
            return True
    
    def load_database(self, master_password):
        """Carga la base de datos encriptada"""
        with open(self.database_file, 'rb') as f:
            data = f.read()
        
        # Extraer salt y datos encriptados
        salt = data[:self.SALT_LENGTH]
        encrypted_data = data[self.SALT_LENGTH:].decode()
        
        # Derivar clave
        self.master_key = self.derive_key(master_password, salt)
        
        # Descifrar datos
        decrypted_json = self.decrypt_data(encrypted_data, self.master_key)
        return json.loads(decrypted_json)
    
    def save_database(self, passwords, salt=None):
        """Guarda la base de datos encriptada"""
        if salt is None and os.path.exists(self.database_file):
            # Recuperar salt existente
            with open(self.database_file, 'rb') as f:
                salt = f.read(self.SALT_LENGTH)
        elif salt is None:
            salt = self.generate_salt()
        
        # Convertir a JSON y cifrar
        json_data = json.dumps(passwords, indent=2)
        encrypted_data = self.encrypt_data(json_data, self.master_key)
        
        # Guardar salt + datos encriptados
        with open(self.database_file, 'wb') as f:
            f.write(salt)
            f.write(encrypted_data.encode())
    
    def add_password(self):
        """Agrega una nueva contraseña"""
        try:
            passwords = self.load_database_content()
            
            print("\n=== AGREGAR NUEVA CONTRASEÑA ===")
            service = input("Nombre del servicio/sitio web: ").strip()
            username = input("Usuario/Email: ").strip()
            
            if not service or not username:
                print("✗ El servicio y usuario son obligatorios")
                return
            
            # Verificar si ya existe
            key = f"{service}:{username}"
            if key in passwords:
                overwrite = input("Esta entrada ya existe. ¿Desea sobrescribirla? (s/N): ")
                if overwrite.lower() != 's':
                    print("Operación cancelada")
                    return
            
            password = getpass.getpass("Contraseña: ")
            if not password:
                print("✗ La contraseña no puede estar vacía")
                return
            
            # Guardar entrada
            passwords[key] = {
                'service': service,
                'username': username,
                'password': password,
                'created': datetime.now().isoformat(),
                'modified': datetime.now().isoformat()
            }
            
            self.save_database(passwords)
            print("✓ Contraseña guardada exitosamente")
            
        except Exception as e:
            print(f"✗ Error al agregar contraseña: {e}")
    
    def list_passwords(self):
        """Lista todas las contraseñas almacenadas"""
        try:
            passwords = self.load_database_content()
            
            if not passwords:
                print("\n=== SIN CONTRASEÑAS ALMACENADAS ===")
                print("No hay contraseñas guardadas en el gestor")
                return
            
            print(f"\n=== CONTRASEÑAS ALMACENADAS ({len(passwords)}) ===")
            print(f"{'#':<3} {'Servicio':<20} {'Usuario':<25} {'Creado':<12}")
            print("-" * 70)
            
            for i, (key, entry) in enumerate(passwords.items(), 1):
                created = entry.get('created', '')[:10]  # Solo fecha
                print(f"{i:<3} {entry['service']:<20} {entry['username']:<25} {created:<12}")
                
        except Exception as e:
            print(f"✗ Error al listar contraseñas: {e}")
    
    def view_password(self):
        """Muestra una contraseña específica"""
        try:
            passwords = self.load_database_content()
            
            if not passwords:
                print("No hay contraseñas almacenadas")
                return
            
            print("\n=== VER CONTRASEÑA ===")
            service = input("Nombre del servicio: ").strip()
            username = input("Usuario/Email: ").strip()
            
            key = f"{service}:{username}"
            if key in passwords:
                entry = passwords[key]
                print(f"\nServicio: {entry['service']}")
                print(f"Usuario: {entry['username']}")
                print(f"Contraseña: {entry['password']}")
                print(f"Creado: {entry.get('created', 'N/A')}")
                print(f"Modificado: {entry.get('modified', 'N/A')}")
            else:
                print("✗ Contraseña no encontrada")
                
        except Exception as e:
            print(f"✗ Error al mostrar contraseña: {e}")
    
    def delete_password(self):
        """Elimina una contraseña"""
        try:
            passwords = self.load_database_content()
            
            if not passwords:
                print("No hay contraseñas para eliminar")
                return
            
            print("\n=== ELIMINAR CONTRASEÑA ===")
            service = input("Nombre del servicio: ").strip()
            username = input("Usuario/Email: ").strip()
            
            key = f"{service}:{username}"
            if key in passwords:
                print(f"Servicio: {passwords[key]['service']}")
                print(f"Usuario: {passwords[key]['username']}")
                
                confirm = input("¿Está seguro de eliminar esta contraseña? (s/N): ")
                if confirm.lower() == 's':
                    del passwords[key]
                    self.save_database(passwords)
                    print("✓ Contraseña eliminada exitosamente")
                else:
                    print("Operación cancelada")
            else:
                print("✗ Contraseña no encontrada")
                
        except Exception as e:
            print(f"✗ Error al eliminar contraseña: {e}")
    
    def load_database_content(self):
        """Carga el contenido de la base de datos"""
        if os.path.exists(self.database_file):
            # Recuperar la contraseña maestra actual
            with open(self.database_file, 'rb') as f:
                salt = f.read(16)
                encrypted_data = f.read().decode()
            
            decrypted_json = self.decrypt_data(encrypted_data, self.master_key)
            return json.loads(decrypted_json)
        return {}
    
    def show_menu(self):
        """Muestra el menú principal"""
        print("\n" + "="*50)
        print("      GESTOR DE CONTRASEÑAS SEGURO")
        print("="*50)
        print("1. Agregar nueva contraseña")
        print("2. Listar contraseñas")
        print("3. Ver contraseña específica")
        print("4. Eliminar contraseña")
        print("5. Salir")
        print("="*50)
    
    def run(self):
        """Ejecuta el gestor de contraseñas"""
        print("GESTOR DE CONTRASEÑAS SEGURO")
        print("Universidad Católica Boliviana 'San Pablo'")
        print("MIS-707 - Fundamentos de Ciberseguridad")
        print("-" * 50)
        
        if not self.authenticate():
            return
        
        while True:
            self.show_menu()
            
            try:
                choice = input("Seleccione una opción (1-5): ").strip()
                
                if choice == '1':
                    self.add_password()
                elif choice == '2':
                    self.list_passwords()
                elif choice == '3':
                    self.view_password()
                elif choice == '4':
                    self.delete_password()
                elif choice == '5':
                    print("\n¡Gracias por usar el Gestor de Contraseñas Seguro!")
                    break
                else:
                    print("✗ Opción inválida. Por favor seleccione 1-5.")
                    
                input("\nPresione Enter para continuar...")
                
            except KeyboardInterrupt:
                print("\n\n¡Hasta luego!")
                break
            except Exception as e:
                print(f"✗ Error inesperado: {e}")

def main():
    """Función principal"""
    manager = SecurePasswordManager()
    manager.run()

if __name__ == "__main__":
    main()