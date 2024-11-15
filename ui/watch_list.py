from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import struct
import json

class WatchList(QWidget):
    def __init__(self, memory_core, parent=None):
        super().__init__(parent)
        self.memory_core = memory_core
        self.layout = QVBoxLayout(self)
        
        # 工具栏
        self.toolbar = QHBoxLayout()
        self.add_btn = QPushButton("添加")
        self.remove_btn = QPushButton("删除")
        self.refresh_btn = QPushButton("刷新")
        self.export_btn = QPushButton("导出")
        self.import_btn = QPushButton("导入")
        
        self.toolbar.addWidget(self.add_btn)
        self.toolbar.addWidget(self.remove_btn)
        self.toolbar.addWidget(self.refresh_btn)
        self.toolbar.addWidget(self.export_btn)
        self.toolbar.addWidget(self.import_btn)
        self.toolbar.addStretch()
        
        self.layout.addLayout(self.toolbar)
        
        # 监视列表
        self.watch_table = QTableWidget()
        self.watch_table.setColumnCount(5)
        self.watch_table.setHorizontalHeaderLabels(["描述", "地址", "类型", "值", "上次值"])
        self.layout.addWidget(self.watch_table)
        
        # 定时刷新
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_values)
        
        # 连接信号
        self.add_btn.clicked.connect(self.add_watch)
        self.remove_btn.clicked.connect(self.remove_watch)
        self.refresh_btn.clicked.connect(self.refresh_values)
        self.watch_table.itemChanged.connect(self.on_item_changed)
        self.export_btn.clicked.connect(self.export_watch_list)
        self.import_btn.clicked.connect(self.import_watch_list)
        
        # 启动定时器
        self.refresh_timer.start(1000)  # 每秒刷新一次
        
    def add_watch(self, address=None, description=None, value_type=None):
        row = self.watch_table.rowCount()
        self.watch_table.insertRow(row)
        
        # 描述
        desc_item = QTableWidgetItem(description or "新监视点")
        desc_item.setFlags(desc_item.flags() | Qt.ItemIsEditable)
        self.watch_table.setItem(row, 0, desc_item)
        
        # 地址
        addr_item = QTableWidgetItem(hex(address) if address else "")
        addr_item.setFlags(addr_item.flags() | Qt.ItemIsEditable)
        self.watch_table.setItem(row, 1, addr_item)
        
        # 类型选择
        type_combo = QComboBox()
        type_combo.addItems([
            "Int8", "UInt8", "Int16", "UInt16",
            "Int32", "UInt32", "Int64", "UInt64",
            "Float", "Double", "Pointer", "String"
        ])
        if value_type:
            type_combo.setCurrentText(value_type)
        self.watch_table.setCellWidget(row, 2, type_combo)
        
        # 值和上次值
        self.watch_table.setItem(row, 3, QTableWidgetItem(""))
        self.watch_table.setItem(row, 4, QTableWidgetItem(""))
    
    def remove_watch(self):
        rows = set(item.row() for item in self.watch_table.selectedItems())
        for row in sorted(rows, reverse=True):
            self.watch_table.removeRow(row)
    
    def refresh_values(self):
        for row in range(self.watch_table.rowCount()):
            try:
                # 获取地址和类型
                addr = int(self.watch_table.item(row, 1).text(), 16)
                type_combo = self.watch_table.cellWidget(row, 2)
                value_type = type_combo.currentText()
                
                # 读取内存
                size = self._get_type_size(value_type)
                data = self.memory_core.read_memory(addr, size)
                
                if data:
                    # 解析值
                    value = self._parse_value(data, value_type)
                    
                    # 更新值
                    current_value = self.watch_table.item(row, 3).text()
                    self.watch_table.item(row, 4).setText(current_value)
                    self.watch_table.item(row, 3).setText(str(value))
                    
            except Exception as e:
                self.watch_table.item(row, 3).setText("Error")
                self.watch_table.item(row, 4).setText("Error")
    
    def _get_type_size(self, value_type):
        sizes = {
            "Int8": 1, "UInt8": 1,
            "Int16": 2, "UInt16": 2,
            "Int32": 4, "UInt32": 4,
            "Int64": 8, "UInt64": 8,
            "Float": 4, "Double": 8,
            "Pointer": 8, "String": 32
        }
        return sizes.get(value_type, 4)
    
    def _parse_value(self, data: bytes, value_type: str):
        formats = {
            "Int8": ("b", 1), "UInt8": ("B", 1),
            "Int16": ("h", 2), "UInt16": ("H", 2),
            "Int32": ("i", 4), "UInt32": ("I", 4),
            "Int64": ("q", 8), "UInt64": ("Q", 8),
            "Float": ("f", 4), "Double": ("d", 8),
            "Pointer": ("Q", 8)
        }
        
        if value_type == "String":
            try:
                return data.decode('utf-8').rstrip('\0')
            except:
                return "Invalid String"
        else:
            fmt, size = formats.get(value_type, ("I", 4))
            value = struct.unpack(fmt, data[:size])[0]
            if value_type == "Pointer":
                return f"0x{value:X}"
            return value
    
    def on_item_changed(self, item):
        if item.column() in [0, 1]:  # 描述或地址改变时刷新值
            self.refresh_values() 
    
    def export_watch_list(self):
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "导出监视列表",
            "",
            "JSON文件 (*.json)"
        )
        if filename:
            data = []
            for row in range(self.watch_table.rowCount()):
                item = {
                    "description": self.watch_table.item(row, 0).text(),
                    "address": self.watch_table.item(row, 1).text(),
                    "type": self.watch_table.cellWidget(row, 2).currentText(),
                    "value": self.watch_table.item(row, 3).text()
                }
                data.append(item)
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
    
    def import_watch_list(self):
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "导入监视列表",
            "",
            "JSON文件 (*.json)"
        )
        if filename:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            for item in data:
                self.add_watch(
                    int(item["address"], 16),
                    item["description"],
                    item["type"]
                )
    