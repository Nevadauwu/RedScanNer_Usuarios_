# 🛡️ RedScanNer_Usuarios_ (Network Auditor & IDS)

> *Hola, he creado este código con ayuda de la IA Gemini. Fue creciendo de parte en parte conforme iba analizando, estudiando el código y ampliándolo. Todo esto con la simple razón de mi aprendizaje y entendimiento en ciberseguridad y programación en Python. Se puede utilizar ya en ambientes reales conteniendo buenas funciones de Capa 4. No me hago responsable sobre algún mal uso del código. Este mismo se irá actualizando conforme siga estudiando. ¡Gracias, espero mínimo les sirva de algo! :)*

---

## 🚀 Características
* **Descubrimiento de Red (Capa 2):** Escaneo masivo ARP para identificar dispositivos activos en la red local.

* **Fingerprinting de S.O.:** Identificación de sistemas operativos combinando TTL de ICMP y consulta de OUI por dirección MAC.

* **Auditoría de Vulnerabilidades (Capa 4):** Detección de puertos expuestos (SMB, Telnet, HTTP, FTP) con evaluación de puntuación de riesgo.

* **Sensor IDS Integrado:** Detección en tiempo real de dispositivos intrusos (*Rogue devices*) y ataques *Man-in-the-Middle* (ARP Spoofing).

* **Consola SOC:** Monitoreo activo de latencia y estado con exportación de reportes ejecutivos en formato JSON.

## 🛠️ Requisitos e Instalación

### Requisitos previos
* Python 3.8 o superior.
* Privilegios de administrador / superusuario (necesario para *raw sockets* con Scapy).

### Instalación
```bash
git clone [https://github.com/Nevadauwu/RedScanNer_Usuarios_.git](https://github.com/Nevadauwu/RedScanNer_Usuarios_.git)
cd RedScanNer_Usuarios_
pip install -r requirements.txt