import re
import json

def parse_snort_alerts(file_path):
    alerts = []
    current_alert = {}
    with open(file_path, 'r') as file:
        lines = file.readlines()

    for line in lines:
        line = line.strip()
        if not line:  # Ignorar líneas vacías
            continue

        # Parsear la línea del título de la alerta
        title_match = re.match(r'\[\*\*\] \[(\d+):(\d+):(\d+)\] (.+) \[\*\*\]', line)
        if title_match:
            if current_alert:  # Guardar la alerta anterior si existe
                alerts.append(current_alert)
            current_alert = {
                "sid": title_match.group(2),
                "generator_id": title_match.group(1),
                "revision": title_match.group(3),
                "message": title_match.group(4),
                "classification": None,
                "priority": None,
                "timestamp": None,
                "source_ip": None,
                "source_port": None,
                "destination_ip": None,
                "destination_port": None,
                "protocol": None,
                "ttl": None,
                "tos": None,
                "id": None,
                "ip_length": None,
                "datagram_length": None,
                "payload_length": None,
                "references": []
            }
            continue

        # Parsear clasificación
        class_match = re.match(r'\[Classification: (.+)\] \[Priority: (\d+)\]', line)
        if class_match and current_alert:
            current_alert["classification"] = class_match.group(1)
            current_alert["priority"] = int(class_match.group(2))
            continue

        # Parsear timestamp, IPs y puertos
        traffic_match = re.match(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+) (.+):(\d+) -> (.+):(\d+)', line)
        if traffic_match and current_alert:
            current_alert["timestamp"] = traffic_match.group(1)
            current_alert["source_ip"] = traffic_match.group(2)
            current_alert["source_port"] = int(traffic_match.group(3))
            current_alert["destination_ip"] = traffic_match.group(4)
            current_alert["destination_port"] = int(traffic_match.group(5))
            continue

        # Parsear detalles del protocolo y metadatos
        proto_match = re.match(r'(\w+) TTL:(\d+) TOS:(0x[0-9A-Fa-f]+) ID:(\d+) IpLen:(\d+) DgmLen:(\d+)', line)
        if proto_match and current_alert:
            current_alert["protocol"] = proto_match.group(1)
            current_alert["ttl"] = int(proto_match.group(2))
            current_alert["tos"] = proto_match.group(3)
            current_alert["id"] = int(proto_match.group(4))
            current_alert["ip_length"] = int(proto_match.group(5))
            current_alert["datagram_length"] = int(proto_match.group(6))
            continue

        # Parsear longitud de la carga útil
        len_match = re.match(r'Len: (\d+)', line)
        if len_match and current_alert:
            current_alert["payload_length"] = int(len_match.group(1))
            continue

        # Parsear referencias (maneja múltiples Xref en una línea)
        xref_matches = re.findall(r'\[Xref => (.+?)\]', line)
        if xref_matches and current_alert:
            current_alert["references"].extend(xref_matches)
            print(f"Referencias encontradas en la línea '{line}': {xref_matches}")  # Depuración
            continue

    # Guardar la última alerta
    if current_alert:
        alerts.append(current_alert)

    return alerts

def save_to_json(alerts, output_file):
    with open(output_file, 'w') as file:
        json.dump(alerts, file, indent=4)

# Configuración para archivo en la misma carpeta
input_file = "alert.ids"  # Cambia esto por el nombre de tu archivo de alertas
output_file = "alerts.json"  # Nombre del archivo JSON de salida
try:
    alerts = parse_snort_alerts(input_file)
    save_to_json(alerts, output_file)
    print(f"Alertas convertidas a JSON y guardadas en {output_file}")
    print(f"Número total de alertas: {len(alerts)}")
except FileNotFoundError:
    print(f"Error: El archivo {input_file} no se encuentra. Asegúrate de que esté en la misma carpeta que el script.")
except Exception as e:
    print(f"Error al procesar el archivo: {str(e)}")
