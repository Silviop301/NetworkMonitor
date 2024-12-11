# Network Monitor

## Monitor de tráfego de rede para detecção de anomalias, geração de relatórios e gerenciamento de logs.

### Funcionalidades
Detecção de anomalias com base em:
Pacotes grandes.
Portas suspeitas.
IPs em lista negra.
Geração de logs rotativos para tráfego geral e eventos suspeitos.
Visualização de gráficos com distribuição de protocolos capturados.
Relatórios em PDF com informações detalhadas de IPs suspeitos e anomalias.

### Instalação
Clone o repositório: git clone <URL_DO_REPOSITORIO>
Instale as dependências: pip install -r requirements.txt

### Configuração
Edite o arquivo config.json com os parâmetros desejados. Exemplo:

json
Copiar código
{
    "size_threshold": 1500,
    "suspect_ports": [23, 3389, 445],
    "log_rotation_size": 100,
    "monitor_interface": "eth0"
}
Certifique-se de que o arquivo blacklist_ips.txt contém os IPs maliciosos que deseja monitorar.

### Uso
Execute o monitor de rede: python monitor.py
Insira a interface de rede para monitorar (ex.: eth0, wlan0 ou outras disponíveis na sua máquina).
Após a captura, o script gerará:
Gráfico de protocolos capturados.
Relatório em PDF com IPs suspeitos (arquivo network_report.pdf).

### Licença
Este projeto está licenciado sob a MIT License.

