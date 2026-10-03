# 🛡️ Local Network Auditor & IDS (Capa 2 / 3 / 4)

Un auditor de red local en tiempo real y sensor de detección de intrusos (IDS) escrito en Python. Esta herramienta está diseñada para estudiantes, entusiastas de la ciberseguridad y administradores que buscan entender cómo inspeccionar su red local, evaluar vulnerabilidades y detectar anomalías.

## 🚀 Características
* **Descubrimiento de Red (Capa 2):** Escaneo masivo ARP para identificar dispositivos activos en la red local.
* **Fingerprinting de S.O.:** Identificación de sistemas operativos combinando TTL de ICMP y consulta de OUI por dirección MAC.
* **Auditoría de Vulnerabilidades (Capa 4):** Detección de puertos expuestos (SMB, Telnet, HTTP, FTP) con evaluación de puntuación de riesgo.
* **Sensor IDS Integrado:** Detección en tiempo real de dispositivos intrusos (*Rogue devices*) y ataques *Man-in-the-Middle* (ARP Spoofing).
* **Consola SOC:** Monitoreo activo de latencia y estado con exportación de reportes ejecutivos en formato JSON.

## 🛠️ Requisitos e Instalación

### Requisitos previos
* Python 3.8 o superior.
* Privilegios de administrador/superusuario (necesario para la creación de *raw sockets* con Scapy).

### Instalación
1. Clona este repositorio:
   ```bash
   git clone [https://github.com/TU_USUARIO/TU_REPOSITORIO.git](https://github.com/TU_USUARIO/TU_REPOSITORIO.git)
   cd TU_REPOSITORIO
   ```
2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## ⚡ Uso

En Linux / WSL / macOS:
```bash
sudo python3 Professional_autoscanner.py
```

En Windows (Terminal como Administrador):
```cmd
python Professional_autoscanner.py
```

## 📝 Licencia
Este proyecto es de código abierto bajo la licencia MIT.