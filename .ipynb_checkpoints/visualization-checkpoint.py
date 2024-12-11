import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
from fpdf import FPDF

class Visualization:
    def __init__(self):
        self.protocol_counts = {}  # Dicionário para contagem de protocolos

    def update_protocol_counts(self, protocol):
        """Atualiza a contagem de pacotes por protocolo."""
        if protocol not in self.protocol_counts:
            self.protocol_counts[protocol] = 1
        else:
            self.protocol_counts[protocol] += 1

    def plot_protocol_distribution(self):
        """Gera um gráfico de barras com a distribuição de protocolos."""
        if not self.protocol_counts:
            print("Nenhum dado disponível para criar o gráfico.")
            return

        protocols = list(self.protocol_counts.keys())
        counts = list(self.protocol_counts.values())

        plt.figure(figsize=(10, 6))
        plt.bar(protocols, counts, color='skyblue')
        plt.title("Distribuição de Protocolos Capturados", fontsize=14)
        plt.xlabel("Protocolos", fontsize=12)
        plt.ylabel("Quantidade de Pacotes", fontsize=12)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    def generate_pdf_report(self, csv_file, output_file):
        """Gera um relatório consolidado em PDF."""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", style="B", size=16)
        pdf.cell(200, 10, txt="Relatório de Monitoramento de Rede", ln=True, align="C")

        # Data e Hora do Relatório
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(10)

        # Resumo de Protocolos
        pdf.set_font("Arial", style="B", size=14)
        pdf.cell(200, 10, txt="Resumo de Protocolos Capturados:", ln=True, align="L")
        pdf.set_font("Arial", size=12)
        for protocol, count in self.protocol_counts.items():
            pdf.cell(200, 10, txt=f"{protocol}: {count} pacotes", ln=True)

        # Dados de IPs Suspeitos
        pdf.ln(10)
        pdf.set_font("Arial", style="B", size=14)
        pdf.cell(200, 10, txt="IPs Suspeitos Detectados:", ln=True, align="L")
        pdf.set_font("Arial", size=12)
        try:
            data = pd.read_csv(csv_file)
            for index, row in data.iterrows():
                pdf.cell(200, 10, txt=f"{row['Timestamp']} | {row['IP']} | {row['Motivo']}", ln=True)
        except FileNotFoundError:
            pdf.cell(200, 10, txt="Erro: Arquivo CSV não encontrado.", ln=True)
        except Exception as e:
            pdf.cell(200, 10, txt=f"Erro ao carregar dados: {e}", ln=True)

        # Salvar o PDF
        try:
            pdf.output(output_file)
            print(f"Relatório salvo em {output_file}")
        except Exception as e:
            print(f"Erro ao salvar o relatório em PDF: {e}")
