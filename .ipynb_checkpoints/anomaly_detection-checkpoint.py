import csv
import os
from datetime import datetime

class AnomalyDetector:
    def __init__(self, size_threshold, suspect_ports, csv_file, blacklist_file):
        self.size_threshold = size_threshold  # Limite de tamanho de pacote
        self.suspect_ports = suspect_ports  # Lista de portas suspeitas
        self.csv_file = csv_file  # Arquivo de IPs suspeitos
        self.blacklist = self.load_blacklist(blacklist_file)  # Carregar lista negra de IPs
        self.suspect_ips = set()  # Conjunto para evitar duplicatas
        self.initialize_csv()

    def load_blacklist(self, file):
        """Carrega a lista negra de IPs de um arquivo."""
        if not os.path.exists(file):
            return set()
        with open(file) as f:
            return set(line.strip() for line in f)

    def initialize_csv(self):
        """Cria o arquivo CSV com cabeçalhos se ainda não existir."""
        try:
            if not os.path.exists(self.csv_file):
                with open(self.csv_file, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Timestamp", "IP", "Motivo"])
        except PermissionError:
            print(f"Erro: Não foi possível criar ou acessar o arquivo {self.csv_file}. Verifique as permissões.")
            exit(1)


    def detect(self, packet):
        """
        Detecta anomalias em um pacote.
        Retorna um dicionário com o status e detalhes do pacote.
        """
        try:
            protocol = packet.highest_layer
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            length = int(packet.length)
            dst_port = int(packet[packet.transport_layer].dstport) if 'TCP' in packet or 'UDP' in packet else None

            # Inicializar lista de motivos de suspeita
            reasons = []

            # Verificar IP na lista negra
            if src_ip in self.blacklist:
                reasons.append("IP na lista negra")

            # Verificar tamanho do pacote
            if length > self.size_threshold:
                reasons.append(f"Pacote muito pesado ({length} bytes)")

            # Verificar porta suspeita
            if dst_port in self.suspect_ports:
                reasons.append(f"Porta suspeita detectada (Porta: {dst_port})")

            # Se houver motivos de suspeita, registrar o IP
            if reasons:
                self.register_suspect(src_ip, ", ".join(reasons))
                return {
                    "is_suspicious": True,
                    "src_ip": src_ip,
                    "reasons": reasons,
                    "protocol": protocol,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "length": length,
                }

            return {"is_suspicious": False}  # Pacote não suspeito

        except AttributeError:
            # Pacote não possui os atributos esperados
            return {"is_suspicious": False}

    def register_suspect(self, ip, motivo):
        """Registra um IP suspeito no conjunto e no arquivo CSV."""
        if ip not in self.suspect_ips:
            self.suspect_ips.add(ip)
            self.log_to_csv(ip, motivo)

    def log_to_csv(self, ip, motivo):
        """Salva o IP suspeito no arquivo CSV."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.csv_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, ip, motivo])
