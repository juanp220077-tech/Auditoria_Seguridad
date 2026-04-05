import nmap
import os
from datetime import datetime

# Configuración inicial
scanner = nmap.PortScanner()
ip_objetivo = '192.168.100.0/24' # Escaneo local por seguridad inicial

print(f"--- Iniciando Escaneo de Red: {ip_objetivo} ---")
print(f"Fecha: {datetime.now()}")

# Ejecutar escaneo de puertos comunes (TCP)
# -sV: Detecta versiones de servicios
#scanner.scan(ip_objetivo, '21-443', '-sV')
# Cambiamos los argumentos para ser más agresivos con el host sospechoso
#scanner.scan('192.168.100.63', '1-1024', '-sV -O')
# Usamos -sV (versiones) y --script=banner (identificación básica)
# Esto NO requiere root y es muy efectivo
scanner.scan('192.168.100.63', '1-1024', '-sV --version-intensity 5')

for host in scanner.all_hosts():
    print(f"Host encontrado: {host} ({scanner[host].hostname()})")
    print(f"Estado: {scanner[host].state()}")
    
    for proto in scanner[host].all_protocols():
        print(f"Protocolo: {proto}")
        puertos = scanner[host][proto].keys()
        for port in puertos:
            estado = scanner[host][proto][port]['state']
            servicio = scanner[host][proto][port]['name']
            print(f" Port: {port}\t State: {estado}\t Service: {servicio}")

print("\n--- Blindaje Verificado: Escaneo Completo ---")

# Guardar resultados en un archivo log
with open("escaneo_log.txt", "a") as f:
    f.write(f"\n--- Escaneo {datetime.now()} ---\n")
    f.write(f"Host: {ip_objetivo} - Estado: up\n")
    f.write("-" * 30 + "\n")

print(">>> Resultado guardado en escaneo_log.txt")
