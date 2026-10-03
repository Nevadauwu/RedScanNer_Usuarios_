import sys
import time
import json
import datetime
import threading
import socket
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor
from scapy.all import conf, sniff, IP, TCP, ICMP, ARP, Ether, sr1, srp

# ==============================================================================
# 1. MOTOR DE EVALUACIÓN DE RIESGOS Y VULNERABILIDADES (RISK ENGINE)
# ==============================================================================

def evaluar_vulnerabilidades(puertos, servicios_str):
    """
    Analiza los puertos y servicios expuestos para calcular un nivel de riesgo
    y generar un vector de auditoría de seguridad.
    """
    hallazgos = []
    puntos_riesgo = 0

    # Vulnerabilidad: SMB / NetBIOS (Riesgo Crítico de Ejecución Remota / Ransomware)
    if 445 in puertos or 139 in puertos or "smb" in servicios_str.lower():
        puntos_riesgo += 40
        hallazgos.append("⚠️ [CRÍTICO] Puerto SMB (445/139) abierto. Vulnerable a ataques de red local / EternalBlue.")

    # Vulnerabilidad: Protocolos legados en texto plano
    if 23 in puertos:
        puntos_riesgo += 30
        hallazgos.append("🔴 [ALTO] Telnet (23) detectado. Tráfico y credenciales sin cifrar.")
    if 21 in puertos:
        puntos_riesgo += 20
        hallazgos.append("🟠 [MEDIO] FTP (21) detectado. Transmisión de archivos en texto plano.")

    # Vulnerabilidad: Interfaz HTTP no cifrada
    if 80 in puertos or 8080 in puertos:
        puntos_riesgo += 10
        hallazgos.append("🟡 [BAJO] Servidor HTTP (80) activo. Panel de administración web expuesto sin TLS/HTTPS.")

    # Clasificación final del nivel de riesgo
    if puntos_riesgo >= 40:
        nivel_riesgo = "🔴 CRÍTICO"
    elif puntos_riesgo >= 25:
        nivel_riesgo = "🟠 ALTO"
    elif puntos_riesgo >= 10:
        nivel_riesgo = "🟡 MEDIO"
    else:
        nivel_riesgo = "🟢 BAJO"

    return {
        "nivel": nivel_riesgo,
        "score": puntos_riesgo,
        "detalles": hallazgos if hallazgos else ["Sin vulnerabilidades críticas visibles."]
    }

# ==============================================================================
# 2. FINGERPRINTING Y DETECCIÓN AVANZADA DE S.O.
# ==============================================================================

def obtener_ttl_real(ip):
    """Envía un paquete ICMP Echo Request para extraer el TTL real de la capa IP."""
    try:
        respuesta = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if respuesta and respuesta.haslayer(IP):
            return respuesta[IP].ttl
    except Exception:
        pass
    return None

def identificar_sistema_operativo(ip, mac_vendor="", servicios="", ttl=None):
    """Cruza TTL, Fabricante OUI y Servicios TCP para deducir el S.O. real."""
    if ttl is None:
        ttl = obtener_ttl_real(ip)

    vendor = str(mac_vendor).lower()
    servicios_str = str(servicios).lower()

    if "smb" in servicios_str or "netbio" in servicios_str or "445" in servicios_str or "139" in servicios_str:
        return "Windows PC"

    if any(v in vendor for v in ["samsung", "xiaomi", "motorola", "oppo", "vivo", "realme", "oneplus"]):
        return "Android"
    
    if "apple" in vendor:
        return "Apple (iOS/macOS)"
        
    if any(v in vendor for v in ["amazon", "roku", "espressif", "tuya", "sonoff", "google"]):
        return "Smart Home / IoT"

    if any(v in vendor for v in ["fiberhome", "zte", "tp-link", "cisco", "technicolor", "arris"]):
        return "Router / Módem"

    if ttl is not None:
        if 65 <= ttl <= 128:
            return "Windows"
        elif ttl <= 64:
            if "mac privada" in vendor or "randomized" in vendor:
                return "Móvil (Android/iOS)"
            return "Linux / Android / macOS"
        elif ttl > 128:
            return "Router / Switch"

    if any(v in vendor for v in ["azurewave", "intel", "realtek", "asustek", "micro-star", "msi", "gigabyte", "dell", "hp"]):
        return "PC / Laptop"

    return "Desconocido"

# ==============================================================================
# 3. SENSOR DE DETECCIÓN DE INTRUSOS (IDS & ANTI-ARP POISONING)
# ==============================================================================

class SensorIDS:
    """Sensor en tiempo real para detectar dispositivos intrusos y ataques Man-in-the-Middle."""
    def __init__(self, macs_autorizadas=None):
        # Lista blanca de MACs conocidas (opcional)
        self.whitelist = set(mac.lower() for mac in macs_autorizadas) if macs_autorizadas else set()

    def auditar_red(self, dispositivos):
        alertas = []
        mac_map = {}

        for dev in dispositivos:
            ip = dev["ip"]
            mac = dev["mac"].lower()

            # 1. Detección de Dispositivo Intruso (Rogue Device)
            if self.whitelist and mac not in self.whitelist:
                alertas.append(f"🚨 [IDS ALERTA] ¡Dispositivo no autorizado detectado! IP: {ip} | MAC: {mac}")

            # 2. Detección de ARP Poisoning / Spoofing (Misma MAC compartida entre múltiples IPs)
            if mac in mac_map:
                ip_existente = mac_map[mac]
                if ip_existente != ip and mac != "ff:ff:ff:ff:ff:ff":
                    alertas.append(f"🔥 [IDS CRÍTICO] Posible Ataque ARP Spoofing (MITM). La MAC {mac} está suplantando a {ip} y {ip_existente}")
            else:
                mac_map[mac] = ip

        return alertas

# ==============================================================================
# 4. MOTOR DE MONITORIZACIÓN Y BANNER GRABBING
# ==============================================================================

def get_network_range():
    """Detecta el segmento /24 local del adaptador por defecto."""
    try:
        local_ip = conf.route.route("0.0.0.0")[1]
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception as e:
        print(f"❌ Error al detectar la red local: {e}")
        sys.exit(1)

def scan_network_arp(network_cidr):
    """Realiza descubrimiento de Capa 2 ARP masivo."""
    arp_request = ARP(pdst=network_cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def obtener_fabricante_mac(mac):
    """Consulta la API pública de MAC Lookup."""
    segundo_caracter = mac[1].lower()
    if segundo_caracter in ['2', '6', 'a', 'e']:
        return "📱 MAC Privada"

    try:
        url = f"https://api.maclookup.app/v2/macs/{mac}"
        respuesta = requests.get(url, timeout=2)
        if respuesta.status_code == 200:
            company = respuesta.json().get("company", "")
            return company if company else "Desconocido"
    except Exception:
        pass
    return "No registrado"

def scan_open_ports(ip, ports=[21, 22, 23, 80, 139, 443, 445, 8080]):
    """Escaneo veloz de puertos TCP."""
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def banner_grabbing(ip, port):
    """Extrae firmas de software de los puertos abiertos."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        s.connect((ip, port))

        if port in [80, 8080, 443]:
            peticion = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            s.sendall(peticion.encode())
            respuesta = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            for linea in respuesta.split('\r\n'):
                if linea.lower().startswith("server:"):
                    return f"Server: {linea.split(':', 1)[1].strip()}"
            return "Web Activa"

        elif port in [21, 22, 23]:
            respuesta = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            return respuesta.split('\n')[0].strip() if respuesta else "Activo"

        elif port == 445:
            s.close()
            return "SMB (Archivos Compartidos)"
        elif port == 139:
            s.close()
            return "NetBIOS Session"

        s.close()
        return "Puerto Abierto"
    except Exception:
        return "Sin respuesta"

def procesar_dispositivo_paralelo(device):
    """Procesa cada IP con soporte multi-hilo."""
    ip = device["ip"]
    mac = device["mac"]

    fabricante = obtener_fabricante_mac(mac)
    puertos = scan_open_ports(ip)

    def procesar_dispositivo_paralelo(device):
    """Procesa cada IP con soporte multi-hilo."""
    ip = device["ip"]
    mac = device["mac"]

    fabricante = obtener_fabricante_mac(mac)
    
    
    scanner_l4 = Layer4Scanner(ip)
    puertos = scanner_l4.escaneo_paralelo_tcp([21, 22, 23, 80, 139, 443, 445, 8080])

    servicios_lista = []
    if puertos:
        for p in puertos:
            banner = banner_grabbing(ip, p)
            servicios_lista.append(f"[{p} -> {banner}]")
        info_servicios = " ".join(servicios_lista)
    else:
        info_servicios = "Ninguno"

    so_real = identificar_sistema_operativo(ip, fabricante, info_servicios)
    eval_riesgo = evaluar_vulnerabilidades(puertos, info_servicios)

    return {
        "ip": ip,
        "mac": mac,
        "fabricante": fabricante,
        "so": so_real,
        "puertos": puertos,
        "servicios": info_servicios,
        "riesgo": eval_riesgo["nivel"],
        "hallazgos": eval_riesgo["detalles"]
    }

    servicios_lista = []
    if puertos:
        for p in puertos:
            banner = banner_grabbing(ip, p)
            servicios_lista.append(f"[{p} -> {banner}]")
        info_servicios = " ".join(servicios_lista)
    else:
        info_servicios = "Ninguno"

    so_real = identificar_sistema_operativo(ip, fabricante, info_servicios)
    eval_riesgo = evaluar_vulnerabilidades(puertos, info_servicios)

    return {
        "ip": ip,
        "mac": mac,
        "fabricante": fabricante,
        "so": so_real,
        "puertos": puertos,
        "servicios": info_servicios,
        "riesgo": eval_riesgo["nivel"],
        "hallazgos": eval_riesgo["detalles"]
    }

# ==============================================================================
# 5. MONITOR EN TIEMPO REAL CON ALERTAS DE SEGURIDAD
# ==============================================================================

class MonitorSOC:
    def __init__(self, dispositivos_iniciales, intervalo=6):
        self.dispositivos = {d["ip"]: d for d in dispositivos_iniciales}
        self.intervalo = intervalo
        self.ejecutando = False
        self.sensor_ids = SensorIDS()

    def _ping_medicion(self, ip):
        inicio = time.time()
        try:
            resp = sr1(IP(dst=ip)/ICMP(), timeout=0.8, verbose=0)
            if resp:
                return round((time.time() - inicio) * 1000, 2)
        except Exception:
            pass
        return None

    def _bucle_soc(self):
        while self.ejecutando:
            for ip, dev in self.dispositivos.items():
                lat = self._ping_medicion(ip)
                dev["latencia"] = f"{lat} ms" if lat is not None else "N/A"
                dev["estado"] = "🟢 Online" if lat is not None else "🔴 Offline"

            # Ejecutar auditoría IDS en cada iteración
            alertas = self.sensor_ids.auditar_red(list(self.dispositivos.values()))
            for alerta in alertas:
                print(f"\n{alerta}")

            time.sleep(self.intervalo)

    def iniciar(self):
        self.ejecutando = True
        self.hilo = threading.Thread(target=self._bucle_soc, daemon=True)
        self.hilo.start()

    def detener(self):
        self.ejecutando = False

    def mostrar_dashboard(self):
        print("\n" + "=" * 100)
        print(f"🛡️  PANEL SOC - AUDITORÍA DE CIBERSEGURIDAD EN TIEMPO REAL [{datetime.datetime.now().strftime('%H:%M:%S')}]")
        print("=" * 100)
        print(f"{'IP':<15} {'ESTADO':<10} {'RIESGO':<12} {'S.O.':<18} {'FABRICANTE':<20} {'SERVICIOS'}")
        print("-" * 100)
        for ip, d in self.dispositivos.items():
            est = d.get("estado", "🟢 Online")
            so_c = d["so"][:16]
            fab_c = d["fabricante"][:18]
            serv_c = d["servicios"][:25] + (".." if len(d["servicios"]) > 25 else "")
            print(f"{d['ip']:<15} {est:<10} {d['riesgo']:<12} {so_c:<18} {fab_c:<20} {serv_c}")
        print("=" * 100)

# ==============================================================================
# 6. BLOQUE PRINCIPAL
# ==============================================================================

if __name__ == '__main__':
    print("⚡ [NIVEL 4] INICIANDO AUDITORÍA MULTICAPA Y IDS DE RED...")
    
    rango_red = get_network_range()
    print(f"📡 Escaneando segmento local: {rango_red}\n")

    t_inicio = time.time()
    raw_devices = scan_network_arp(rango_red)

    if raw_devices:
        # Ejecución paralela de escaneo de puertos y evaluación de riesgos
        with ThreadPoolExecutor(max_workers=10) as executor:
            resultados = list(executor.map(procesar_dispositivo_paralelo, raw_devices))

        t_duracion = round(time.time() - t_inicio, 2)
        print(f"✅ Escaneo e inspección completados en {t_duracion} segundos.")

        # Guardar informe ejecutivo en JSON
        archivo_reporte = f"reporte_soc_nivel4_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(archivo_reporte, "w", encoding="utf-8") as f:
            json.dump(resultados, f, indent=4, ensure_ascii=False)
        print(f"📁 Informe ejecutivo de ciberseguridad guardado: {archivo_reporte}\n")

        # Resumen de hallazgos de vulnerabilidades en consola
        print("🔍 RESUMEN DE VULNERABILIDADES DETECTADAS:")
        print("=" * 80)
        for dev in resultados:
            if dev["hallazgos"] and dev["hallazgos"][0] != "Sin vulnerabilidades críticas visibles.":
                print(f"📌 Dispositivo {dev['ip']} ({dev['so']}) - Riesgo: {dev['riesgo']}")
                for h in dev["hallazgos"]:
                    print(f"   └── {h}")
        print("=" * 80)

        # Iniciar consola de monitoreo SOC continuo
        monitor_soc = MonitorSOC(resultados, intervalo=8)
        monitor_soc.iniciar()
        print("\n🚀 Sensor IDS y Monitoreo SOC activados. Presiona Ctrl+C para finalizar.\n")

        try:
            while True:
                time.sleep(12)
                monitor_soc.mostrar_dashboard()
        except KeyboardInterrupt:
            print("\n🛑 Apagando sensor IDS y finalizando auditoría...")
            monitor_soc.detener()
    else:
        print("⚠️ No se encontraron dispositivos activos en la red.")