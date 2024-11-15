from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QTableWidget, QPushButton, QMenu, QTableWidgetItem, QHeaderView, QMessageBox, QComboBox, QLabel
from PyQt5.QtCore import Qt, pyqtSignal
from core.process_manager import ProcessManager
import logging
import frida

logger = logging.getLogger(__name__)

class ProcessSelector(QWidget):
    process_selected = pyqtSignal(int)  # 发送选中的进程PID
    
    def __init__(self, process_manager, parent=None):
        super().__init__(parent)
        self.process_manager = process_manager
        self.init_ui()
    
    def init_ui(self):
        self.layout = QVBoxLayout(self)
        
        # 搜索框
        self.search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索进程...")
        self.search_input.textChanged.connect(self.filter_processes)
        self.search_layout.addWidget(self.search_input)
        self.layout.addLayout(self.search_layout)
        
        # 进程列表
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["PID", "进程名", "路径", "内存使用", "CPU使用"])
        self.process_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.process_table.customContextMenuRequested.connect(self.show_context_menu)
        
        # 设置列宽
        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        
        self.layout.addWidget(self.process_table)
        
        # 刷新按钮
        self.toolbar = QHBoxLayout()
        self.refresh_btn = QPushButton("刷新进程列表")
        self.refresh_btn.clicked.connect(self.refresh_process_list)
        self.toolbar.addWidget(self.refresh_btn)
        self.toolbar.addStretch()
        self.layout.addLayout(self.toolbar)
        
        # 初始加载进程列表
        self.refresh_process_list()
    
    def refresh_process_list(self):
        """刷新进程列表"""
        processes = self.process_manager.refresh_process_list()
        self.update_table(processes)
        
    def filter_processes(self):
        """根据搜索框内容过滤进程"""
        filter_text = self.search_input.text()
        self.process_manager.set_filter(filter_text)
        self.update_table(self.process_manager._filtered_processes)
        
    def update_table(self, processes):
        """更新表格内容"""
        self.process_table.setRowCount(0)
        for proc in processes:
            row = self.process_table.rowCount()
            self.process_table.insertRow(row)
            
            self.process_table.setItem(row, 0, QTableWidgetItem(str(proc.pid)))
            self.process_table.setItem(row, 1, QTableWidgetItem(proc.name))
            self.process_table.setItem(row, 2, QTableWidgetItem(proc.path))
            self.process_table.setItem(row, 3, QTableWidgetItem(f"{proc.memory_usage:.1f} MB"))
            self.process_table.setItem(row, 4, QTableWidgetItem(f"{proc.cpu_usage:.1f}%"))
            
    def show_context_menu(self, pos):
        menu = QMenu()
        attach_action = menu.addAction("附加到进程")
        action = menu.exec_(self.process_table.mapToGlobal(pos))
        
        if action == attach_action:
            current_row = self.process_table.currentRow()
            if current_row >= 0:
                pid = int(self.process_table.item(current_row, 0).text())
                self.attach_to_process(pid)
    
    def attach_to_process(self, pid):
        """发送进程选择信号"""
        try:
            # 获取进程信息
            process_info = self.process_manager.get_process_info(pid)
            if not process_info:
                raise Exception("无法获取进程信息")
            
            # 发送进程选择信号
            self.process_selected.emit(pid)
            
        except Exception as e:
            logger.error(f"附加到进程失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"附加到进程失败: {str(e)}")