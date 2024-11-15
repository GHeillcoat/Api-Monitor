from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QSplitter, QTabWidget, QStatusBar, QMessageBox,
                           QListWidget, QStackedWidget, QLabel, QLineEdit, QTextEdit, QPlainTextEdit, QPushButton, QTableWidget, QHeaderView, QComboBox, QScrollBar, QCheckBox, QRadioButton)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QColor, QFont
from .process_selector import ProcessSelector
from .hook_manager import HookManager
from .memory_scanner import MemoryScanner
from .script_editor import FridaScriptEditor
from .log_viewer import LogViewer
from core.memory_core import MemoryCore
from core.process_manager import ProcessManager
from core.hook_core import HookCore
from core.logger import logger
from .memory_browser import MemoryBrowser

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("API Monitor")
        self.resize(1200, 800)
        
        # VSCode 配色方案
        self.vscode_colors = {
            'background': QColor('#1E1E1E'),
            'sidebar': QColor('#252526'),
            'active_tab': QColor('#1E1E1E'),
            'inactive_tab': QColor('#2D2D2D'),
            'text': QColor('#D4D4D4'),
            'selected': QColor('#37373D'),
            'highlight': QColor('#264F78'),
            'border': QColor('#404040')
        }
        
        # 设置应用样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1E1E1E;
                color: #D4D4D4;
            }
            QListWidget {
                background-color: #252526;
                color: #D4D4D4;
                border: none;
                outline: none;
            }
            QListWidget::item {
                padding: 8px;
                border: none;
            }
            QListWidget::item:selected {
                background-color: #37373D;
                color: #FFFFFF;
            }
            QListWidget::item:hover {
                background-color: #2D2D2D;
            }
            QStackedWidget {
                background-color: #1E1E1E;
                border-left: 1px solid #404040;
            }
            QStatusBar {
                background-color: #007ACC;
                color: white;
            }
            QSplitter::handle {
                background-color: #404040;
            }
            QTabWidget::pane {
                border: none;
            }
            QWidget {
                background-color: #1E1E1E;
                color: #D4D4D4;
            }
            
            /* 输入框样式 */
            QLineEdit, QTextEdit, QPlainTextEdit {
                background-color: #1E1E1E;
                border: 1px solid #404040;
                border-radius: 4px;
                padding: 5px;
                color: #D4D4D4;
            }
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
                border: 1px solid #007ACC;
            }
            
            /* 按钮样式 */
            QPushButton {
                background-color: #2D2D2D;
                border: 1px solid #404040;
                border-radius: 4px;
                padding: 5px 15px;
                color: #D4D4D4;
                min-height: 25px;
            }
            QPushButton:hover {
                background-color: #37373D;
            }
            QPushButton:pressed {
                background-color: #515151;
            }
            QPushButton:disabled {
                background-color: #2D2D2D;
                color: #666666;
            }
            
            /* 表格样式 */
            QTableWidget {
                background-color: #1E1E1E;
                border: 1px solid #404040;
                gridline-color: #404040;
            }
            QTableWidget::item {
                padding: 5px;
                color: #D4D4D4;
            }
            QHeaderView::section {
                background-color: #333333;
                color: white;
                padding: 5px;
                border: none;
                border-right: 1px solid #404040;
                border-bottom: 1px solid #404040;
            }
            QTableWidget::item:selected {
                background-color: #264F78;
            }
            
            /* 下拉框样式 */
            QComboBox {
                background-color: #2D2D2D;
                border: 1px solid #404040;
                border-radius: 4px;
                padding: 5px;
                color: #D4D4D4;
                min-height: 25px;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #D4D4D4;
                margin-right: 5px;
            }
            QComboBox:on {
                background-color: #37373D;
            }
            QComboBox QAbstractItemView {
                background-color: #2D2D2D;
                border: 1px solid #404040;
                selection-background-color: #37373D;
                selection-color: #D4D4D4;
            }
            
            /* 滚动条样式 */
            QScrollBar:vertical {
                background-color: #1E1E1E;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #424242;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #4F4F4F;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background-color: #1E1E1E;
            }
            
            /* 水平滚动条 */
            QScrollBar:horizontal {
                background-color: #1E1E1E;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background-color: #424242;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #4F4F4F;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background-color: #1E1E1E;
            }
            
            /* 复选框样式 */
            QCheckBox {
                color: #D4D4D4;
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
                border: 1px solid #404040;
            }
            QCheckBox::indicator:unchecked {
                background-color: #1E1E1E;
            }
            QCheckBox::indicator:checked {
                background-color: #007ACC;
                image: url(check.png);  /* 需要添加一个勾选图标 */
            }
            
            /* 单选框样式 */
            QRadioButton {
                color: #D4D4D4;
                spacing: 5px;
            }
            QRadioButton::indicator {
                width: 18px;
                height: 18px;
                border-radius: 9px;
                border: 1px solid #404040;
            }
            QRadioButton::indicator:unchecked {
                background-color: #1E1E1E;
            }
            QRadioButton::indicator:checked {
                background-color: #007ACC;
                border: 4px solid #1E1E1E;
            }
        """)
        
        # 初始化核心组件
        self.process_manager = ProcessManager()
        self.memory_core = MemoryCore()
        self.hook_core = HookCore()
        
        self.init_ui()
        self.setup_status_bar()
        
    def init_ui(self):
        # 创建主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # 创建主布局
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 创建左侧菜单
        self.menu_list = QListWidget()
        self.menu_list.setFixedWidth(200)
        self.menu_list.addItems([
            "进程列表",
            "Hook管理",
            "内存扫描",
            "内存浏览",
            "脚本编辑"
        ])
        
        # 创建堆叠部件
        self.stack = QStackedWidget()
        
        # 创建垂直分割器（上方内容和下方日志）
        content_splitter = QSplitter(Qt.Vertical)
        
        # 添加各个页面到堆叠部件
        self.process_selector = ProcessSelector(self.process_manager)
        self.process_selector.process_selected.connect(self.on_process_selected)
        self.stack.addWidget(self.process_selector)
        
        self.hook_manager = HookManager()
        self.stack.addWidget(self.hook_manager)
        
        self.memory_scanner = MemoryScanner(self.memory_core)
        self.stack.addWidget(self.memory_scanner)
        
        self.memory_browser = MemoryBrowser(self.memory_core)
        self.stack.addWidget(self.memory_browser)
        
        self.script_editor = FridaScriptEditor()
        self.script_editor.set_hook_core(self.hook_core)
        self.stack.addWidget(self.script_editor)
        
        # 连接菜单切换信号
        self.menu_list.currentRowChanged.connect(self.stack.setCurrentIndex)
        
        # 添加堆叠部件到分割器
        content_splitter.addWidget(self.stack)
        
        # 创建并添加日志查看器
        self.log_viewer = LogViewer()
        content_splitter.addWidget(self.log_viewer)
        
        # 设置分割器的初始大小比例（7:3）
        content_splitter.setSizes([700, 300])
        
        # 添加组件到主布局
        main_layout.addWidget(self.menu_list)
        main_layout.addWidget(content_splitter)
        
        # 禁用需要先附加进程的菜单项
        self.set_tabs_enabled(False)
        
        # 选择第一个菜单项
        self.menu_list.setCurrentRow(0)
    
    def set_tabs_enabled(self, enabled: bool):
        """启用/禁用需要先附加进程的菜单项"""
        for i in range(1, self.menu_list.count()):  # 跳过进程列表
            item = self.menu_list.item(i)
            item.setFlags(item.flags() | Qt.ItemIsEnabled if enabled else item.flags() & ~Qt.ItemIsEnabled)
    
    def on_process_selected(self, pid):
        """处理进程选择"""
        try:
            logger.info(f"[MainWindow] 开始处理进程选择: {pid}")
            
            # 获取进程信息
            logger.debug("[MainWindow] 正在获取进程信息...")
            process_info = self.process_manager.get_process_info(pid)
            if not process_info:
                raise Exception("无法获取进程信息")
            
            if not process_info.is_accessible:
                raise Exception("没有足够的权限访问此进程")
            
            # 附加到进程
            logger.debug("[MainWindow] 正在附加MemoryCore...")
            self.memory_core.attach_process(pid)
            
            logger.debug("[MainWindow] 正在附加HookCore...")
            self.hook_core.attach_process(pid)
            
            # 更新脚本编辑器的 hook_core
            self.script_editor.set_hook_core(self.hook_core)
            
            # 更新UI
            self.setWindowTitle(f"API Monitor - {process_info.name} ({pid})")
            self.set_tabs_enabled(True)
            self.status_bar.showMessage(f"已附加到进程: {process_info.name} ({pid})")
            
            logger.info(f"[MainWindow] 成功附加到进程: {process_info.name} ({pid})")
            
        except Exception as e:
            logger.error(f"[MainWindow] 附加进程失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"附加进程失败: {str(e)}")
            self.status_bar.showMessage("附加进程失败")
            self.set_tabs_enabled(False)
    
    def setup_status_bar(self):
        """设置状态栏"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("准备就绪")
    
    def closeEvent(self, event):
        """窗口关闭事件"""
        try:
            # 清理资源
            if self.memory_core:
                self.memory_core.cleanup()
            event.accept()
        except Exception as e:
            logger.error(f"关闭窗口时发生错误: {str(e)}")
            event.accept()