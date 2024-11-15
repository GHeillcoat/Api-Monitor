from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QMetaType
from PyQt5.QtGui import QColor, QTextCharFormat, QBrush, QFont
from PyQt5.QtCore import pyqtSlot

# 注册自定义类型
try:
    from PyQt5.QtCore import QTextCursor
    QMetaType.type("QTextCursor")
except:
    pass

class MessageHandler(QObject):
    message_signal = pyqtSignal(str, str)  # (text, level)

class ScriptOutputWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.Window | Qt.WindowStaysOnTopHint)
        self.setWindowTitle("脚本输出")
        self.resize(600, 400)
        self.init_ui()
        
        # 创建消息处理器
        self.message_handler = MessageHandler()
        self.message_handler.message_signal.connect(self._append_message)
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # 输出文本框
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        
        # 设置样式
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #404040;
                font-family: Consolas, monospace;
                font-size: 11pt;
            }
        """)
        
        # 工具栏
        toolbar = QHBoxLayout()
        self.clear_btn = QPushButton("清除")
        self.clear_btn.clicked.connect(self.clear_output)
        toolbar.addStretch()
        toolbar.addWidget(self.clear_btn)
        
        layout.addWidget(self.output_text)
        layout.addLayout(toolbar)
        
        # 预定义格式
        self.formats = {
            'default': self._create_format("#D4D4D4"),
            'debug': self._create_format("#4EC9B0"),
            'info': self._create_format("#569CD6"),
            'warning': self._create_format("#CE9178"),
            'error': self._create_format("#F44747"),
            'separator': self._create_format("#808080")
        }
    
    def _create_format(self, color):
        fmt = QTextCharFormat()
        fmt.setForeground(QBrush(QColor(color)))
        fmt.setFont(QFont("Consolas", 11))
        return fmt
    
    @pyqtSlot()
    def clear_output(self):
        """清除输出内容"""
        self.output_text.clear()
    
    def append_message(self, text, level='default'):
        """通过信号发送消息"""
        self.message_handler.message_signal.emit(text, level)
    
    @pyqtSlot(str, str)
    def _append_message(self, text, level):
        """实际添加消息的槽函数"""
        cursor = self.output_text.textCursor()
        cursor.movePosition(cursor.End)
        cursor.insertText(text + '\n', self.formats.get(level, self.formats['default']))
        self.output_text.setTextCursor(cursor)
        self.output_text.ensureCursorVisible() 