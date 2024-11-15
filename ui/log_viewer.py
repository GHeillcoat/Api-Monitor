from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QCheckBox, QComboBox, QLabel, QLineEdit
from PyQt5.QtGui import QTextCharFormat, QColor, QTextCursor
from PyQt5.QtCore import Qt
from core.logger import LogLevel, logger

class LogViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.all_logs = []  # 存储所有日志
        
        # 设置日志颜色
        self.log_colors = {
            LogLevel.DEBUG: QColor("#CCCCCC"),    # 灰色
            LogLevel.INFO: QColor("#FFFFFF"),     # 白色
            LogLevel.WARNING: QColor("#FFCC00"),  # 黄色
            LogLevel.ERROR: QColor("#FF0000"),    # 红色
            LogLevel.CRITICAL: QColor("#FF00FF")  # 紫色
        }
        
        # 设置Hook日志的特殊颜色
        self.hook_colors = {
            "separator": QColor("#00CCCC"),     # 分隔符
            "function": QColor("#FFCC00"),      # 函数调用
            "param_name": QColor("#00CC00"),    # 参数名
            "param_value": QColor("#FFFFFF"),   # 参数值
            "stack_title": QColor("#CC00CC"),   # 调用堆栈标题
            "stack_content": QColor("#808080"), # 调用堆栈内容
            "return": QColor("#0088FF"),        # 返回值
            "error": QColor("#FF0000")          # 错误信息
        }
        
        # 连接日志信号
        logger.log_signal.connect(self.append_log)
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # 创建日志文本框
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("background-color: #1E1E1E;")  # 深色背景
        layout.addWidget(self.log_text)
        
        # 创建工具栏
        toolbar = QHBoxLayout()
        
        # 添加自动滚动选项
        self.auto_scroll = QCheckBox("自动滚动")
        self.auto_scroll.setChecked(True)
        toolbar.addWidget(self.auto_scroll)
        
        # 添加日志级别过滤
        self.level_combo = QComboBox()
        self.level_combo.addItems(["全部", "调试", "信息", "警告", "错误", "严重"])
        self.level_combo.currentTextChanged.connect(self.filter_logs)
        toolbar.addWidget(QLabel("日志级别:"))
        toolbar.addWidget(self.level_combo)
        
        # 添加搜索框
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索日志...")
        self.search_input.textChanged.connect(self.filter_logs)
        toolbar.addWidget(self.search_input)
        
        toolbar.addStretch()
        layout.addLayout(toolbar)
    
    def append_log(self, message: str, level: int):
        """添加日志"""
        # 存储日志
        self.all_logs.append((message, level))
        
        # 创建文本格式
        format = QTextCharFormat()
        format.setForeground(self.log_colors.get(level, QColor("#FFFFFF")))
        
        # 如果是Hook日志，使用特殊格式
        if message.startswith("[HOOK]"):
            self._format_hook_log(message)
        else:
            # 添加普通日志
            cursor = self.log_text.textCursor()
            cursor.movePosition(QTextCursor.End)
            cursor.insertText(message + "\n", format)
        
        # 自动滚动
        if self.auto_scroll.isChecked():
            self.log_text.verticalScrollBar().setValue(
                self.log_text.verticalScrollBar().maximum()
            )
    
    def _format_hook_log(self, message: str):
        """格式化Hook日志"""
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        # 分析并格式化Hook日志
        parts = message.split(" | ")
        for part in parts:
            format = QTextCharFormat()
            
            if "函数调用:" in part:
                format.setForeground(self.hook_colors["function"])
            elif "参数:" in part:
                format.setForeground(self.hook_colors["param_name"])
            elif "返回值:" in part:
                format.setForeground(self.hook_colors["return"])
            elif "调用堆栈:" in part:
                format.setForeground(self.hook_colors["stack_title"])
            elif "错误:" in part:
                format.setForeground(self.hook_colors["error"])
            else:
                format.setForeground(self.hook_colors["param_value"])
            
            cursor.insertText(part + " | ", format)
        
        cursor.insertText("\n")
    
    def filter_logs(self):
        """过滤日志"""
        level_text = self.level_combo.currentText()
        search_text = self.search_input.text().lower()
        
        # 清空日志显示
        self.log_text.clear()
        
        # 获取选中的日志级别
        level_map = {
            "全部": None,
            "调试": LogLevel.DEBUG,
            "信息": LogLevel.INFO,
            "警告": LogLevel.WARNING,
            "错误": LogLevel.ERROR,
            "严重": LogLevel.CRITICAL
        }
        selected_level = level_map[level_text]
        
        # 重新显示符合条件的日志
        for message, level in self.all_logs:
            if (selected_level is None or level == selected_level) and \
               (not search_text or search_text in message.lower()):
                self.append_log(message, level) 