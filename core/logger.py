import logging
from PyQt5.QtCore import QObject, pyqtSignal

# 添加 LogLevel 类
class LogLevel:
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

class QtHandler(logging.Handler):
    def __init__(self, signal):
        super().__init__()
        self.signal = signal

    def emit(self, record):
        msg = self.format(record)
        self.signal.emit(msg, record.levelno)

class Logger(QObject):
    log_signal = pyqtSignal(str, int)  # 信号：消息文本, 日志级别

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger('APIMonitor')
        self.logger.setLevel(logging.DEBUG)
        
        # 添加Qt处理器
        qt_handler = QtHandler(self.log_signal)
        qt_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        self.logger.addHandler(qt_handler)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

# 创建全局logger实例
logger = Logger() 