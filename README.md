# Gestor de Contraseñas Seguro

## Descripción General del Proyecto

Gestor de contraseñas desarrollado para la materia **MIS-707 - Fundamentos de Ciberseguridad** de la Universidad Católica Boliviana "San Pablo" - Sede Tarija.

Esta aplicación implementa un sistema seguro de almacenamiento y gestión de contraseñas utilizando técnicas criptográficas modernas, incluyendo cifrado simétrico AES-256-GCM, derivación de claves PBKDF2, y almacenamiento encriptado de datos.

### Características Principales

- **Cifrado AES-256-GCM**: Protección de datos con algoritmo de cifrado de grado militar
- **Derivación PBKDF2**: 100,000 iteraciones con SHA-256 para resistencia contra ataques de fuerza bruta
- **Contraseña Maestra**: Sistema de autenticación único para acceso a todas las credenciales
- **Almacenamiento Seguro**: Base de datos completamente encriptada sin información en texto plano
- **Interfaz de Consola**: Sistema CRUD completo para gestión de contraseñas

## Dependencias

### Requisitos del Sistema
- **Python**: 3.6 o superior
- **Sistema Operativo**: Windows, Linux, macOS

### Librerías Requeridas
- **cryptography**: 3.4.8 o superior

## Cómo Ejecutar la Aplicación

### 1. Instalación de Dependencias

```bash
# Instalar la librería criptográfica requerida
pip install cryptography
```

O usando el archivo requirements.txt:

```bash
pip install -r requirements.txt
```

### 2. Ejecución del Programa

```bash
# Ejecutar desde la línea de comandos
python password_manager.py
```

```bash
# Ejecutar desde la línea de comandos linux
python3 password_manager.py
```

### 3. Primera Configuración

En la primera ejecución, el sistema solicitará:
- **Crear contraseña maestra** (mínimo 8 caracteres)
- **Confirmar contraseña maestra**

Una vez configurado, se creará automáticamente el archivo `passwords.enc` con la base de datos encriptada.

### 4. Uso del Sistema

El programa presenta un menú con 5 opciones:
1. **Agregar nueva contraseña** - Crear nuevas entradas
2. **Listar contraseñas** - Ver todas las entradas almacenadas
3. **Ver contraseña específica** - Mostrar detalles de una entrada
4. **Eliminar contraseña** - Borrar entradas existentes
5. **Salir** - Cerrar la aplicación

## Estructura de Archivos

```
gestor-contraseñas-seguro/
├── password_manager.py    # Código principal del gestor
├── requirements.txt       # Dependencias del proyecto
├── README.md             # Esta documentación
└── passwords.enc         # Base de datos encriptada (se crea automáticamente)
```

## Funcionalidades Implementadas

### Gestión de Contraseñas
- **Crear**: Agregar nuevas credenciales (servicio, usuario, contraseña)
- **Leer**: Listar todas las entradas y ver detalles específicos
- **Actualizar**: Sobrescribir entradas existentes
- **Eliminar**: Borrar entradas con confirmación de seguridad

### Seguridad
- **Autenticación**: Contraseña maestra requerida en cada sesión
- **Cifrado**: AES-256-GCM para protección de datos
- **Derivación de claves**: PBKDF2 con 100,000 iteraciones
- **Integridad**: Verificación automática de manipulación de datos

## Tecnologías Utilizadas

- **Lenguaje**: Python 3.8+
- **Cifrado**: AES-256 en modo GCM
- **Derivación de claves**: PBKDF2 con SHA-256
- **Librería criptográfica**: Python Cryptography
- **Interfaz**: Aplicación de consola

## Seguridad Implementada

El sistema utiliza las siguientes medidas de seguridad:
- Cifrado simétrico AES-256-GCM para confidencialidad e integridad
- Derivación de claves PBKDF2 con salt aleatorio de 16 bytes
- 100,000 iteraciones para resistencia a ataques de fuerza bruta
- Vector de inicialización (IV) único para cada operación de cifrado
- Sin almacenamiento de contraseñas o claves en texto plano

## Autor

**[Edgar Mollo Flores]**  
Universidad Católica Boliviana "San Pablo" - Sede Tarija  
MIS-707 - Fundamentos de Ciberseguridad  
Profesor: Msc. Davis Mendoza

## Notas Importantes

- **Propósito Académico**: Este proyecto fue desarrollado con fines educativos
- **Contraseña Maestra**: No olvides tu contraseña maestra, ya que no es posible recuperar los datos sin ella
- **Base de Datos**: El archivo `passwords.enc` contiene todos tus datos encriptados
- **Backup**: Se recomienda hacer copias de seguridad del archivo `passwords.enc`