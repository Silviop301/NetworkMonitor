import logging
import os

class LoggerManager:
    def __init__(self, log_file, max_size_mb, log_format='%(asctime)s - %(levelname)s - %(message)s', max_rotations=10):
        self.log_file = log_file  # Nome do arquivo de log
        self.max_size_bytes = max_size_mb * 1024 * 1024  # Tamanho máximo em bytes
        self.log_format = log_format  # Formato do log
        self.max_rotations = max_rotations  # Limite máximo de rotações
        self.logger = logging.getLogger(log_file)  # Logger associado ao arquivo
        self.logger.setLevel(logging.INFO)  # Nível padrão de log
        self.setup_handler()

    def setup_handler(self):
        """Configura o manipulador de logs com rotação automática."""
        self.rotate_log()  # Rotaciona logs existentes, se necessário
        handler = logging.FileHandler(self.log_file, mode='a')
        handler.setFormatter(logging.Formatter(self.log_format))
        # Adiciona o handler em vez de sobrescrever todos os existentes
        if not any(isinstance(h, logging.FileHandler) and h.baseFilename == handler.baseFilename for h in self.logger.handlers):
            self.logger.addHandler(handler)

    def rotate_log(self):
        """Roda o log se exceder o tamanho máximo configurado."""
        if os.path.exists(self.log_file) and os.path.getsize(self.log_file) >= self.max_size_bytes:
            for i in range(1, self.max_rotations + 1):  # Limite configurável para rotação
                rotated_file = f"{self.log_file}.{i}"
                if not os.path.exists(rotated_file):
                    os.rename(self.log_file, rotated_file)
                    break

    def log(self, message, level="info", additional_info=None):
        """Registra mensagens no log."""
        if additional_info:
            message = f"{message} | Info adicional: {additional_info}"
        
        if level == "info":
            self.logger.info(message)
        elif level == "warning":
            self.logger.warning(message)
        elif level == "error":
            self.logger.error(message)
        else:
            self.logger.debug(message)

    def log_network_traffic(self, src_ip, dst_ip, protocol, length, dst_port=None):
        """Registra informações detalhadas do tráfego de rede."""
        message = (
            f"Tráfego Capturado: Origem={src_ip}, Destino={dst_ip}, Protocolo={protocol}, "
            f"Tamanho={length} bytes, Porta Destino={dst_port if dst_port else 'N/A'}"
        )
        self.logger.info(message)

    def log_exception(self, message):
        """Registra exceções no log com nível de erro."""
        self.logger.error(message, exc_info=True)

    def log_critical(self, message):
        """Registra mensagens críticas no log."""
        self.logger.critical(message)
