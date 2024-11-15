from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, 
                           QPushButton, QHBoxLayout, QInputDialog, QDialog, 
                           QLabel, QLineEdit, QComboBox, QGridLayout, QFileDialog, QMessageBox)
from PyQt5.QtGui import QColor
from core.logger import logger
from core.hook_core import HookCore
import json

class ParamDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("参数设置")
        self.params = []  # [(alias, type), ...]
        self.init_ui()
        
    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.params_layout = QGridLayout()
        self.layout.addLayout(self.params_layout)
        
        # 添加参数按钮
        self.add_btn = QPushButton("添加参数")
        self.add_btn.clicked.connect(self.add_param_row)
        self.layout.addWidget(self.add_btn)
        
        # 确定取消按钮
        buttons = QHBoxLayout()
        self.ok_btn = QPushButton("确定")
        self.cancel_btn = QPushButton("取消")
        self.ok_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(self.ok_btn)
        buttons.addWidget(self.cancel_btn)
        self.layout.addLayout(buttons)
        
        # 添加第一个参数行
        self.add_param_row()
    
    def add_param_row(self):
        row = len(self.params)
        
        # 参数序号
        self.params_layout.addWidget(QLabel(f"参数{row}:"), row, 0)
        
        # 参数别名
        alias = QLineEdit()
        alias.setPlaceholderText(f"param{row}")
        self.params_layout.addWidget(alias, row, 1)
        
        # 参数类型
        type_combo = QComboBox()
        type_combo.addItems([
            "指针(ptr)", "整数(int)", "整数(uint)", "长整数(int64)",
            "浮点(float)", "双精度(double)", "字符串(ascii)", 
            "字符串(unicode)", "字节数组(bytes)"
        ])
        self.params_layout.addWidget(type_combo, row, 2)
        
        self.params.append((alias, type_combo))
    
    def get_params(self):
        return [(alias.text() or f"param{i}", type_combo.currentText())
                for i, (alias, type_combo) in enumerate(self.params)]

class HookManager(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.process_id = None
        self.hooks = []  # 存储当前的Hook信息
        self.hook_core = HookCore()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # 创建工具栏
        toolbar = QHBoxLayout()
        self.add_hook_btn = QPushButton("添加Hook")
        self.remove_hook_btn = QPushButton("移除Hook")
        self.export_btn = QPushButton("导出Hook")  # 新增导出按钮
        self.import_btn = QPushButton("导入Hook")  # 新增导入按钮
        toolbar.addWidget(self.add_hook_btn)
        toolbar.addWidget(self.remove_hook_btn)
        toolbar.addWidget(self.export_btn)
        toolbar.addWidget(self.import_btn)
        toolbar.addStretch()
        
        # 连接按钮点击事件
        self.add_hook_btn.clicked.connect(self.on_add_hook_clicked)
        self.remove_hook_btn.clicked.connect(self.on_remove_hook_clicked)
        self.export_btn.clicked.connect(self.export_hooks)  # 连接导出事件
        self.import_btn.clicked.connect(self.import_hooks)  # 连接导入事件
        
        # 创建Hook列表
        self.hook_table = QTableWidget()
        self.hook_table.setColumnCount(4)  # 减少一列(移除状态列)
        self.hook_table.setHorizontalHeaderLabels(["地址", "偏移", "参数个数", "注释"])
        
        layout.addLayout(toolbar)
        layout.addWidget(self.hook_table)
        
        # 允许双击编辑注释
        self.hook_table.itemDoubleClicked.connect(self.on_item_double_clicked)
    
    def set_process(self, pid):
        """设置当前进程"""
        self.process_id = pid
        logger.info(f"Hook管理器已设置目标进程: {pid}")
        # 清空现有的Hook
        self.hook_table.setRowCount(0)
        self.hooks.clear()
        # 附加到进程
        try:
            self.hook_core.attach_process(pid)
        except Exception as e:
            logger.error(f"Hook核心附加进程失败: {str(e)}")
    
    def add_hook(self, address_str, num_args, params):
        """添加Hook"""
        try:
            hook_info = self.parse_hook_address(address_str)
            hook_info['num_args'] = num_args
            hook_info['params'] = params
            
            # 根据Hook类型调用不同的Hook方法
            if hook_info['type'] == 'export':
                self.hook_core.hook_function(
                    hook_info['dll'], 
                    hook_info['function'],
                    params
                )
            elif hook_info['type'] == 'offset':
                self.hook_core.hook_custom_address(
                    str(hook_info['base']),
                    hook_info['offset'],
                    num_args,
                    params
                )
            
            self.hooks.append(hook_info)
            self.update_hook_table()
            logger.info(f"添加Hook: {address_str} 参数个数: {num_args}")
        except ValueError as e:
            logger.error(f"添加Hook失败: {str(e)}")
        except Exception as e:
            logger.error(f"Hook执行失败: {str(e)}")
    
    def remove_hook(self, index):
        """移除Hook"""
        if 0 <= index < len(self.hooks):
            removed_hook = self.hooks.pop(index)
            self.update_hook_table()
            logger.info(f"移除Hook: {removed_hook}")
    
    def update_hook_table(self):
        """更新Hook列表显示"""
        self.hook_table.setRowCount(len(self.hooks))
        for row, hook in enumerate(self.hooks):
            if hook['type'] == 'export':
                self.hook_table.setItem(row, 0, QTableWidgetItem(hook['dll']))
                self.hook_table.setItem(row, 1, QTableWidgetItem(hook['function']))
            else:
                self.hook_table.setItem(row, 0, QTableWidgetItem(hex(hook['base'])))
                self.hook_table.setItem(row, 1, QTableWidgetItem(hex(hook['offset'])))
            
            self.hook_table.setItem(row, 2, QTableWidgetItem(str(hook['num_args'])))
            self.hook_table.setItem(row, 3, QTableWidgetItem(hook.get('comment', '')))
    
    def on_add_hook_clicked(self):
        # 获取Hook地址
        address_str, ok = QInputDialog.getText(
            self, "添加Hook", 
            "输入Hook地址 (格式: DLL!函数名 或 基地址+偏移):"
        )
        if not ok or not address_str:
            return
            
        # 获取参数设置
        param_dialog = ParamDialog(self)
        if param_dialog.exec_() != QDialog.Accepted:
            return
            
        params = param_dialog.get_params()
        
        # 添加Hook
        self.add_hook(address_str, len(params), params)
    
    def on_remove_hook_clicked(self):
        # 获取当前选中的行
        current_row = self.hook_table.currentRow()
        if current_row >= 0:
            self.remove_hook(current_row)
    
    def parse_hook_address(self, address_str):
        """解析Hook地址"""
        if '!' in address_str:
            # DLL名称!导出函数名称
            dll_name, func_name = address_str.split('!')
            return {'type': 'export', 'dll': dll_name, 'function': func_name}
        elif '+' in address_str:
            # 基地址+偏移
            base, offset = address_str.split('+')
            return {'type': 'offset', 'base': int(base, 16), 'offset': int(offset, 16)}
        else:
            raise ValueError("无效的Hook地址格式")
    
    def export_hooks(self):
        """导出Hook配置"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "导出Hook配置",
            "",
            "JSON文件 (*.json)"
        )
        if filename:
            try:
                data = []
                for hook in self.hooks:
                    hook_data = {
                        'type': hook['type'],
                        'dll': hook.get('dll'),
                        'function': hook.get('function'),
                        'base': hook.get('base'),
                        'offset': hook.get('offset'),
                        'num_args': hook['num_args'],
                        'params': hook['params'],
                        'comment': hook.get('comment', '')
                    }
                    data.append(hook_data)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                logger.info(f"Hook配置已导出到: {filename}")
                
            except Exception as e:
                logger.error(f"导出Hook配置失败: {str(e)}")
                QMessageBox.warning(self, "错误", f"导出失败: {str(e)}")
    
    def import_hooks(self):
        """导入Hook配置"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "导入Hook配置",
            "",
            "JSON文件 (*.json)"
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 清除现有的Hook
                self.hooks.clear()
                
                # 导入新的Hook
                for hook_data in data:
                    try:
                        if hook_data['type'] == 'export':
                            self.hook_core.hook_function(
                                hook_data['dll'],
                                hook_data['function'],
                                hook_data['params']
                            )
                        else:
                            self.hook_core.hook_custom_address(
                                str(hook_data['base']),
                                hook_data['offset'],
                                hook_data['num_args'],
                                hook_data['params']
                            )
                        
                        self.hooks.append(hook_data)
                        
                    except Exception as e:
                        logger.error(f"导入Hook失败: {str(e)}")
                        continue
                
                self.update_hook_table()
                logger.info(f"已从 {filename} 导入Hook配置")
                
            except Exception as e:
                logger.error(f"导入Hook配置失败: {str(e)}")
                QMessageBox.warning(self, "错误", f"导入失败: {str(e)}")
    
    def on_item_double_clicked(self, item):
        """处理双击事件"""
        if self.hook_table.column(item) == 3:  # 注释列
            row = self.hook_table.row(item)
            comment, ok = QInputDialog.getText(
                self,
                "编辑注释",
                "输入注释:",
                text=item.text()
            )
            if ok:
                self.hooks[row]['comment'] = comment
                self.update_hook_table()