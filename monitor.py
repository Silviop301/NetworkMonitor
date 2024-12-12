import pyshark
import json
import socket
from logger import LoggerManager
from anomaly_detection import AnomalyDetector
from visualization import Visualization

# Carregar configurações do arquivo config.json
try:
    with open("config.json") as config_file:
        config = json.load(config_file)
except FileNotFoundError:
    print("Erro: Arquivo config.json não encontrado.")
    exit(1)

# Obter o IP da máquina local
def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"Erro ao obter o IP local: {e}")
        return "127.0.0.1"

local_ip = get_local_ip()

# Inicializar componentes do sistema
general_logger = LoggerManager("network_traffic.log", config["log_rotation_size"])
suspect_logger = LoggerManager("network_suspects.log", config["log_rotation_size"])
detector = AnomalyDetector(
    size_threshold=config["size_threshold"],
    suspect_ports=config["suspect_ports"],
    csv_file="suspect_ips.csv",
    blacklist_file="blacklist_ips.txt"
)
viz = Visualization()

def display_packet_info(result):
    """Exibe informações do pacote no terminal."""
    print("\n--- Pacote Capturado ---")
    print(f"Protocolo: {result.get('protocol')}")
    print(f"Origem: {result.get('src_ip')}")
    print(f"Destino: {result.get('dst_ip')}")
    print(f"Porta de Destino: {result.get('dst_port')}")
    print(f"Tamanho: {result.get('length')} bytes")
    if result.get("is_suspicious"):
        print(f"\033[91mALERTA: {', '.join(result['reasons'])}\033[0m")  # Texto vermelho para alertas

def monitor_traffic(interface):
    """Monitora o tráfego na interface de rede especificada."""
    print(f"Iniciando monitoramento na interface: {interface}")

    try:
        # Captura pacotes em tempo real
        capture = pyshark.LiveCapture(interface=interface)
        total_packets = 0
        suspicious_packets = 0

        for packet in capture.sniff_continuously():
            total_packets += 1

            try:
                # Capturar informações detalhadas do pacote
                protocol = packet.highest_layer
                src_ip = packet.ip.src if hasattr(packet, 'ip') else None
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
                length = int(packet.length)
                dst_port = (
                    int(packet[packet.transport_layer].dstport)
                    if hasattr(packet, "transport_layer") and packet.transport_layer in ["TCP", "UDP"]
                    else None
                )

                # Ignorar pacotes do IP local
                if src_ip == local_ip:
                    general_logger.log(f"Pacote ignorado do IP local: {src_ip}")
                    continue

                # Registrar informações detalhadas no log
                general_logger.log_network_traffic(src_ip, dst_ip, protocol, length, dst_port)

                # Detectar anomalias no pacote
                result = detector.detect(packet)

                if result["is_suspicious"]:
                    suspicious_packets += 1
                    suspect_logger.log(f"ALERTA: {result['reasons']} | {result}")
                    viz.update_protocol_counts(result["protocol"])
                    display_packet_info(result)

                # Atualizar contagem no terminal
                print(f"\rTotal de Pacotes: {total_packets} | Suspeitos: {suspicious_packets}", end="")

            except AttributeError:
                general_logger.log("Pacote ignorado devido a atributos ausentes.", level="warning")

    except KeyboardInterrupt:
        print("\nMonitoramento interrompido pelo usuário.")
        print("Gerando relatórios e gráficos...")
        try:
            viz.plot_protocol_distribution()
            viz.generate_pdf_report("suspect_ips.csv", "network_report.pdf")
        except Exception as e:
            print(f"Erro ao gerar relatórios: {e}")
    except Exception as e:
        general_logger.log_exception(f"Erro ao monitorar tráfego: {e}")

if __name__ == "__main__":
    try:
        # Solicitar interface de rede ao usuário
        interface = input(f"Digite a interface de rede para monitorar (padrão: {config['monitor_interface']}): ") or config["monitor_interface"]
        monitor_traffic(interface)
    except Exception as e:
        print(f"Erro crítico: {e}")
