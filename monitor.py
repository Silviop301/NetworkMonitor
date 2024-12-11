import pyshark
import json
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

            # Detectar anomalias no pacote
            result = detector.detect(packet)

            # Atualizar logs e visualizações
            general_logger.log(f"Pacote capturado: {result}")
            if result["is_suspicious"]:
                suspicious_packets += 1
                suspect_logger.log(f"ALERTA: {result['reasons']} | {result}")
                viz.update_protocol_counts(result["protocol"])
                display_packet_info(result)

            # Atualizar contagem no terminal
            print(f"\rTotal de Pacotes: {total_packets} | Suspeitos: {suspicious_packets}", end="")

    except KeyboardInterrupt:
        print("\nMonitoramento interrompido pelo usuário.")
        print("Gerando relatórios e gráficos...")
        try:
            viz.plot_protocol_distribution()
            viz.generate_pdf_report("suspect_ips.csv", "network_report.pdf")
        except Exception as e:
            print(f"Erro ao gerar relatórios: {e}")
    except Exception as e:
        print(f"Erro ao monitorar tráfego: {e}")


if __name__ == "__main__":
    try:
        # Solicitar interface de rede ao usuário
        interface = input(f"Digite a interface de rede para monitorar (padrão: {config['monitor_interface']}): ") or config["monitor_interface"]
        monitor_traffic(interface)
    except Exception as e:
        print(f"Erro crítico: {e}")
