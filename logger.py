import logging
import os

class LoggerManager:
    def __init__(self, log_file, max_size_mb):
        self.log_file = log_file  # Nome do arquivo de log
        self.max_size_bytes = max_size_mb * 1024 * 1024  # Tamanho máximo em bytes
        self.logger = logging.getLogger(log_file)  # Logger associado ao arquivo
        self.logger.setLevel(logging.INFO)  # Nível padrão de log
        self.setup_handler()

    def setup_handler(self):
        """Configura o manipulador de logs com rotação automática."""
        self.rotate_log()  # Rotaciona logs existentes, se necessário
        handler = logging.FileHandler(self.log_file, mode='a')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.logger.handlers = [handler]

    def rotate_log(self):
        """Roda o log se exceder o tamanho máximo configurado."""
        if os.path.exists(self.log_file) and os.path.getsize(self.log_file) >= self.max_size_bytes:
            for i in range(1, 1000):  # Limite arbitrário para rotação
                rotated_file = f"{self.log_file}.{i}"
                if not os.path.exists(rotated_file):
                    os.rename(self.log_file, rotated_file)
                    break

    def log(self, message, level="info"):
        """Registra mensagens no log."""
        if level == "info":
            self.logger.info(message)
        elif level == "warning":
            self.logger.warning(message)
        elif level == "error":
            self.logger.error(message)
