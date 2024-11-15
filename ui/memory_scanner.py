from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                           QTableWidget, QTableWidgetItem, QComboBox, QLineEdit, 
                           QLabel, QProgressBar, QMessageBox, QMenu, QGroupBox,
                           QMainWindow)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QTimer
from .memory_browser import MemoryBrowser
import logging
from typing import Any

logger = logging.getLogger(__name__)

class SearchWorker(QThread):
    finished = pyqtSignal(list)  # 搜索完成信号
    progress = pyqtSignal(int, int, str)  # 进度信号 (当前值, 总数, 状态文本)
    error = pyqtSignal(str)      # 错误信号

    def __init__(self, memory_core, value_type, value, previous_results=None, start_addr=None, end_addr=None):
        super().__init__()
        self.memory_core = memory_core
        self.value_type = value_type
        self.value = value
        self.previous_results = previous_results
        self.start_addr = start_addr
        self.end_addr = end_addr
        
        # 添加消息处理器
        if self.memory_core.script:
            self.memory_core.script.on('message', self._on_message)

    def _on_message(self, message, data):
        """处理来自JS的消息"""
        if message['type'] == 'send':
            payload = message.get('payload', {})
            if isinstance(payload, dict) and payload.get('type') == 'progress':
                self.progress.emit(
                    payload['current'],
                    payload['total'],
                    payload['status']
                )

    def run(self):
        try:
            results = self.memory_core.search_memory(
                self.value_type,
                self.value,
                self.previous_results,
                self.start_addr,
                self.end_addr
            )
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))

class MemoryScanner(QWidget):
    def __init__(self, memory_core, parent=None):
        super().__init__(parent)
        self.memory_core = memory_core
        self.init_ui()
        self.scan_results = []
        
        # 添加定时器以定期刷新值
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_values)
        self.refresh_timer.start(1000)  # 每秒刷新一次

    def init_ui(self):
        main_layout = QHBoxLayout(self)  # 改为水平布局
        
        # 左侧扫描控制和结果区域
        left_layout = QVBoxLayout()
        
        # 扫描控制区域
        control_layout = QHBoxLayout()
        
        # 值类型选
        self.type_combo = QComboBox()
        self.type_combo.addItems([
            "字节 (1字节)", 
            "2字节", 
            "4字节",
            "8字节",
            "单浮点数",
            "双浮点数",
            "字符串",
            "宽字符串"
        ])
        control_layout.addWidget(QLabel("值类型:"))
        control_layout.addWidget(self.type_combo)
        
        # 值输入框
        self.value_input = QLineEdit()
        self.value_input.setPlaceholderText("输入要搜索的值...")
        control_layout.addWidget(QLabel("值:"))
        control_layout.addWidget(self.value_input)
        
        left_layout.addLayout(control_layout)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_label = QLabel()
        self.progress_label.setVisible(False)
        
        left_layout.addWidget(self.progress_bar)
        left_layout.addWidget(self.progress_label)
        
        # 结表格
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(2)
        self.result_table.setHorizontalHeaderLabels(["地址", "值"])
        self.result_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.result_table.customContextMenuRequested.connect(self.show_context_menu)
        left_layout.addWidget(self.result_table)
        
        main_layout.addLayout(left_layout)
        
        # 右侧控制面板
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # 地址范围设置
        range_group = QGroupBox("搜索范围")
        range_layout = QVBoxLayout()
        
        # 起始地址
        start_layout = QHBoxLayout()
        self.start_addr_input = QLineEdit()
        self.start_addr_input.setPlaceholderText("起始地址 (默认: 0x0)")
        self.start_addr_input.setText("0x0")  # 设置默认值
        start_layout.addWidget(QLabel("起始:"))
        start_layout.addWidget(self.start_addr_input)
        range_layout.addLayout(start_layout)
        
        # 结束地址
        end_layout = QHBoxLayout()
        self.end_addr_input = QLineEdit()
        self.end_addr_input.setPlaceholderText("结束地址 (默认: 0x7fffffffffff)")
        self.end_addr_input.setText("0x7fffffffffff")  # 设置默认值
        end_layout.addWidget(QLabel("结束:"))
        end_layout.addWidget(self.end_addr_input)
        range_layout.addLayout(end_layout)
        
        range_group.setLayout(range_layout)
        right_layout.addWidget(range_group)
        
        # 描按钮组
        scan_group = QGroupBox("扫描控制")
        scan_layout = QVBoxLayout()
        
        self.first_scan_btn = QPushButton("首次扫描")
        self.next_scan_btn = QPushButton("再次扫描")
        
        self.first_scan_btn.clicked.connect(self.start_first_scan)
        self.next_scan_btn.clicked.connect(self.start_next_scan)
        
        # 初始状态设置
        self.next_scan_btn.setEnabled(False)
        
        scan_layout.addWidget(self.first_scan_btn)
        scan_layout.addWidget(self.next_scan_btn)
        
        scan_group.setLayout(scan_layout)
        right_layout.addWidget(scan_group)
        
        # 添加内存修改组
        modify_group = QGroupBox("内存修改")
        modify_layout = QVBoxLayout()
        
        # 修改值输入
        value_layout = QHBoxLayout()
        self.modify_value_input = QLineEdit()
        self.modify_value_input.setPlaceholderText("输入新的值...")
        value_layout.addWidget(QLabel("新值:"))
        value_layout.addWidget(self.modify_value_input)
        modify_layout.addLayout(value_layout)
        
        # 改按钮
        button_layout = QHBoxLayout()
        self.modify_selected_btn = QPushButton("修改选中")
        self.modify_all_btn = QPushButton("修改全部")
        
        self.modify_selected_btn.clicked.connect(self.modify_selected_value)
        self.modify_all_btn.clicked.connect(self.modify_all_values)
        
        button_layout.addWidget(self.modify_selected_btn)
        button_layout.addWidget(self.modify_all_btn)
        modify_layout.addLayout(button_layout)
        
        modify_group.setLayout(modify_layout)
        right_layout.addWidget(modify_group)
        
        right_layout.addStretch()
        main_layout.addWidget(right_panel)
        
    def start_first_scan(self):
        """首次扫描"""
        if not self.memory_core.script:
            QMessageBox.warning(self, "错误", "请先附加到目标进程")
            return
            
        value = self.value_input.text()
        if not value:
            QMessageBox.warning(self, "错误", "请输入要搜索的值")
            return
            
        # 获取地址范围
        try:
            start_addr = int(self.start_addr_input.text(), 16) if self.start_addr_input.text() else 0x0
            end_addr = int(self.end_addr_input.text(), 16) if self.end_addr_input.text() else 0x7fffffffffff
        except ValueError:
            QMessageBox.warning(self, "错误", "地址格式错误，请使用16进制格式 (0x...)")
            return
            
        # 清空之前结果
        self.scan_results = []
        self.result_table.setRowCount(0)
        
        # 禁用扫描按钮
        self.first_scan_btn.setEnabled(False)
        self.next_scan_btn.setEnabled(False)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # 创建并启动搜索线程
        self.search_worker = SearchWorker(
            self.memory_core,
            self._get_value_type(self.type_combo.currentText()),
            value,
            start_addr=start_addr,
            end_addr=end_addr
        )
        self.search_worker.finished.connect(self.first_scan_completed)
        self.search_worker.progress.connect(self.update_progress)
        self.search_worker.error.connect(self.search_error)
        self.search_worker.start()
        
    def start_next_scan(self):
        """再次扫描"""
        if not self.scan_results:
            QMessageBox.warning(self, "错误", "请先进行首次扫描")
            return
            
        value = self.value_input.text()
        if not value:
            QMessageBox.warning(self, "错误", "请输入要搜索的值")
            return
            
        # 禁用所有扫描按钮
        self.first_scan_btn.setEnabled(False)
        self.next_scan_btn.setEnabled(False)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # 创建并启动搜索线程
        self.search_worker = SearchWorker(
            self.memory_core,
            self._get_value_type(self.type_combo.currentText()),
            value,
            previous_results=self.scan_results
        )
        self.search_worker.finished.connect(self.next_scan_completed)
        self.search_worker.progress.connect(self.update_progress)
        self.search_worker.error.connect(self.search_error)
        self.search_worker.start()
        
    def first_scan_completed(self, results):
        """首次扫描完成处理"""
        self.scan_results = results
        self.update_results_table(results)
        
        # 启用按钮
        self.first_scan_btn.setEnabled(True)
        self.next_scan_btn.setEnabled(True)
        
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        # 更新按钮文本
        self.first_scan_btn.setText("新的扫描")
        
    def next_scan_completed(self, results):
        """再次扫描完成处理"""
        self.scan_results = results
        self.update_results_table(results)
        
        # 启用按钮
        self.first_scan_btn.setEnabled(True)
        self.next_scan_btn.setEnabled(True)
        
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
    
    def show_context_menu(self, position):
        """显示右键菜单"""
        menu = QMenu()
        
        # 获取选中的项
        selected_items = self.result_table.selectedItems()
        if not selected_items:
            return
        
        # 获取选中行的地址
        row = self.result_table.row(selected_items[0])
        addr_item = self.result_table.item(row, 0)
        if not addr_item:
            return
        
        address = int(addr_item.text(), 16)
        
        # 添加菜单项
        watch_read_action = menu.addAction("监控读取")
        watch_write_action = menu.addAction("监控写入")
        watch_exec_action = menu.addAction("监控执行")
        browse_action = menu.addAction("在内存浏览器中查看")
        menu.addSeparator()
        copy_addr_action = menu.addAction("复制地址")
        copy_value_action = menu.addAction("复制值")
        menu.addSeparator()
        modify_action = menu.addAction("修改值")
        
        # 显示菜单并获取选择的动作
        action = menu.exec_(self.result_table.viewport().mapToGlobal(position))
        
        if action == watch_read_action:
            self.watch_address(address, 'r')
        elif action == watch_write_action:
            self.watch_address(address, 'w')
        elif action == watch_exec_action:
            self.watch_address(address, 'x')
        elif action == browse_action:
            self.browse_memory(address)
        elif action == copy_addr_action:
            self.copy_address(address)
        elif action == copy_value_action:
            self.copy_value(row)
        elif action == modify_action:
            self.show_modify_dialog(row)
    
    def browse_memory(self, address):
        """在内存浏览器中查看"""
        try:
            # 获取主窗口的内存浏览器实例
            main_window = self.window()
            if isinstance(main_window, QMainWindow):
                # 切换到内存浏览器页面
                for i in range(main_window.stack.count()):
                    if isinstance(main_window.stack.widget(i), MemoryBrowser):
                        main_window.stack.setCurrentIndex(i)
                        main_window.menu_list.setCurrentRow(i)
                        # 使用正确的方法名
                        main_window.memory_browser.navigate_to_address(address)
                        break
        except Exception as e:
            logger.error(f"[MemoryScanner] 打开内存浏览器失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"打开内存浏览器失败: {str(e)}")
    
    def copy_address(self, address):
        """复制地址到剪贴板"""
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(hex(address))
    
    def copy_value(self, row):
        """复制值到剪贴板"""
        from PyQt5.QtWidgets import QApplication
        value_item = self.result_table.item(row, 1)
        if value_item:
            QApplication.clipboard().setText(value_item.text())
    
    def show_modify_dialog(self, row):
        """显示修改值对话框"""
        try:
            addr_item = self.result_table.item(row, 0)
            value_item = self.result_table.item(row, 1)
            if not addr_item or not value_item:
                return
            
            address = int(addr_item.text(), 16)
            current_value = value_item.text()
            
            # 获取新值
            from PyQt5.QtWidgets import QInputDialog
            new_value, ok = QInputDialog.getText(
                self,
                "修改值",
                "请输入新值:",
                text=current_value
            )
            
            if ok and new_value:
                # 获取当前的值类型
                value_type = self._get_value_type(self.type_combo.currentText())
                
                # 处理输入值
                if new_value.lower().startswith('0x'):
                    processed_value = int(new_value, 16)
                elif value_type in ["Float", "Double"]:
                    processed_value = float(new_value)
                else:
                    processed_value = int(new_value)
                
                # 写入内存
                if self.write_value_to_memory(address, processed_value, value_type):
                    # 更新表格显示
                    value_item.setText(str(processed_value))
                    QMessageBox.information(self, "成功", "值修改成功")
                else:
                    QMessageBox.warning(self, "错误", "写入内存失败")
                    
        except ValueError:
            QMessageBox.warning(self, "错误", "输入值格式错误")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"修改值失败: {str(e)}")
    
    def _get_value_type(self, display_type: str) -> str:
        """将显示的类型名转换为实际的搜索类型"""
        type_map = {
            "字节 (1字节)": "UInt8",
            "2字节": "UInt16",
            "4字节": "UInt32",
            "8字节": "UInt64",
            "单浮点数": "Float",
            "双浮点数": "Double",
            "字符串": "String",
            "宽字符串": "UTF-16 String",
            "字节数组": "Bytes",
            "二进制": "Binary"
        }
        return type_map.get(display_type, "UInt32")
    
    def update_progress(self, current, total, status):
        """更新进度条"""
        progress = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(progress)
        self.progress_label.setText(status)
    
    def search_error(self, error_msg):
        """搜索错误处理"""
        QMessageBox.critical(self, "错误", f"搜索失败: {error_msg}")
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
    
    def update_results_table(self, results):
        """更新结果表格"""
        self.result_table.setRowCount(len(results))
        for row, (addr, value) in enumerate(results):
            # 检查addr是否为字符串，如果是则转换为整数
            if isinstance(addr, str):
                # 如果地址已经是16进制字符串格式，直接使用
                if addr.startswith('0x'):
                    addr_str = addr
                else:
                    # 否则添加0x前缀
                    addr_str = f"0x{addr}"
            else:
                # 如果是数字，则格式化为16进制
                addr_str = f"0x{addr:X}"
            
            self.result_table.setItem(row, 0, QTableWidgetItem(addr_str))
            self.result_table.setItem(row, 1, QTableWidgetItem(str(value)))
    
    def modify_selected_value(self):
        """修改选中的内存值"""
        selected_rows = self.result_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "错误", "请先选择要修改的内存地址")
            return
        
        value = self.modify_value_input.text()
        if not value:
            QMessageBox.warning(self, "错误", "请输入要修改的值")
            return
        
        try:
            # 获取当前的值类型
            value_type = self._get_value_type(self.type_combo.currentText())
            
            # 处理输入值
            if value.lower().startswith('0x'):
                processed_value = int(value, 16)
            elif value_type in ["Float", "Double"]:
                processed_value = float(value)
            else:
                processed_value = int(value)
            
            # 获取选中的行
            rows = set(item.row() for item in selected_rows)
            for row in rows:
                addr_item = self.result_table.item(row, 0)
                if addr_item:
                    addr = int(addr_item.text(), 16)
                    # 根据类型写入内存
                    self.write_value_to_memory(addr, processed_value, value_type)
                    # 更新表格显示
                    self.result_table.item(row, 1).setText(str(processed_value))
                
            QMessageBox.information(self, "成功", "内存值修改成功")
            
        except ValueError:
            QMessageBox.warning(self, "错误", "输入值格式错误")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"修改内存失败: {str(e)}")
    
    def modify_all_values(self):
        """修改所有搜索结果的内存值"""
        if not self.scan_results:
            QMessageBox.warning(self, "错误", "没有可修改的搜索结果")
            return
        
        value = self.modify_value_input.text()
        if not value:
            QMessageBox.warning(self, "错误", "请输入要修改的值")
            return
        
        try:
            # 获取当前的值类型
            value_type = self._get_value_type(self.type_combo.currentText())
            
            # 处理输入值
            if value.lower().startswith('0x'):
                processed_value = int(value, 16)
            elif value_type in ["Float", "Double"]:
                processed_value = float(value)
            else:
                processed_value = int(value)
            
            # 修改所有结果
            for row in range(self.result_table.rowCount()):
                addr_item = self.result_table.item(row, 0)
                if addr_item:
                    addr = int(addr_item.text(), 16)
                    # 根据类型写入内存
                    self.write_value_to_memory(addr, processed_value, value_type)
                    # 更新表格显示
                    self.result_table.item(row, 1).setText(str(processed_value))
                
            QMessageBox.information(self, "成功", "所有内存值修改成功")
            
        except ValueError:
            QMessageBox.warning(self, "错误", "输入值格式错误")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"修改内存失败: {str(e)}")
    
    def write_value_to_memory(self, address: int, value: Any, value_type: str):
        """根据类写入内存值"""
        # 直接使用新的写入函数
        if not self.memory_core.write_value(address, value, value_type):
            raise Exception("写入内存失败")
    
    def watch_address(self, address, mode='rw'):
        """监控指定地址"""
        try:
            # 获取当前的值类型
            value_type = self._get_value_type(self.type_combo.currentText())
            type_sizes = {
                "UInt8": 1, "Int8": 1,
                "UInt16": 2, "Int16": 2,
                "UInt32": 4, "Int32": 4,
                "UInt64": 8, "Int64": 8,
                "Float": 4,
                "Double": 8,
                "String": 4
            }
            monitor_size = type_sizes.get(value_type, 4)
            
            # 创建输出窗口
            from .script_output import ScriptOutputWindow
            output_window = ScriptOutputWindow()
            output_window.show()
            
            # 获取主窗口的 hook_core
            main_window = self.window()
            if not isinstance(main_window, QMainWindow) or not hasattr(main_window, 'hook_core'):
                raise Exception("无法获取 hook_core")
            
            hook_core = main_window.hook_core
            
            # 生成监控脚本
            script_text = f"""
            (function() {{
                const monitorAddr = ptr('{hex(address)}');
                const monitorSize = {monitor_size};
                const thread = Process.enumerateThreads()[0];
                
                send('[DEBUG] 初始化监控: 地址=' + monitorAddr + ', 大小=' + monitorSize);
                
                Process.setExceptionHandler(e => {{
                    send('[DEBUG] ===== 检测到内存访问 =====');
                    send('[DEBUG] 地址: ' + e.context.pc);
                    send('[DEBUG] 访问类型: ' + e.type);
                    
                    // 获取模块信息
                    const moduleMap = new ModuleMap();
                    const moduleDetails = moduleMap.find(e.context.pc);
                    if (moduleDetails) {{
                        send('[DEBUG] 所属模块: ' + moduleDetails.name + ' (基址: ' + moduleDetails.base + ')');
                    }}
                    
                    // 获取调用堆栈
                    const backtrace = Thread.backtrace(e.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress)
                        .filter(addr => addr.toString().indexOf('(null)') === -1);
                        
                    send('[DEBUG] 调用堆栈:\\n' + backtrace.join('\\n'));
                    
                    if (Process.getCurrentThreadId() === thread.id &&
                        ['breakpoint', 'single-step'].includes(e.type)) {{
                        thread.unsetHardwareWatchpoint(0);
                        send('[DEBUG] 已禁用硬件监视点');
                        // 重新设置断点
                        thread.setHardwareWatchpoint(0, monitorAddr, monitorSize, '{mode}');
                        send('[DEBUG] 重新设置硬件监视点');
                        return true;
                    }}
                    
                    send('[DEBUG] 传递给应用程序');
                    return false;
                }});
                
                thread.setHardwareWatchpoint(0, monitorAddr, monitorSize, '{mode}');
                send('[DEBUG] 内存监控已启动');
                send('[DEBUG] 监控地址: ' + monitorAddr);
                send('[DEBUG] 监控大小: ' + monitorSize + ' 字节');
                
                // 保持脚本运行
                setInterval(() => {{}}, 1000);
            }})();
            """
            
            # 创建并运行脚本
            script = hook_core.session.create_script(script_text)
            
            # 设置消息处理
            def on_message(message, data):
                if message['type'] == 'send':
                    output_window.append_message(message['payload'])
                elif message['type'] == 'error':
                    output_window.append_message(f"错误: {message['description']}", 'error')
            
            script.on('message', on_message)
            script.load()
            
            # 保存引用防止被垃圾回收
            if not hasattr(self, '_monitors'):
                self._monitors = []
            self._monitors.append({
                'script': script,
                'output': output_window
            })
            
            output_window.append_message(f"开始监控地址: {hex(address)}", 'info')
            
        except Exception as e:
            logger.error(f"[MemoryScanner] 设置内存监控失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"设置内存监控失败: {str(e)}")
    
    def refresh_values(self):
        """刷新列表中的值"""
        for row in range(self.result_table.rowCount()):
            addr_item = self.result_table.item(row, 0)
            if addr_item:
                address = int(addr_item.text(), 16)
                value_type = self._get_value_type(self.type_combo.currentText())
                size = self._get_type_size(value_type)
                data = self.memory_core.read_memory(address, size)
                if data:
                    value = self._parse_value(data, value_type)
                    self.result_table.item(row, 1).setText(str(value))
    
    def _get_type_size(self, value_type):
        """获取指定值类型的大小"""
        sizes = {
            "UInt8": 1, "Int8": 1,
            "UInt16": 2, "Int16": 2,
            "UInt32": 4, "Int32": 4,
            "UInt64": 8, "Int64": 8,
            "Float": 4, "Double": 8,
            "String": 32, "UTF-16 String": 64,  # 假设字符串的最大长度
            "Bytes": 32, "Binary": 32  # 假设字节数组的最大长度
        }
        return sizes.get(value_type, 4)  # 默认返回4字节
    
    def _parse_value(self, data, value_type):
        """解析从内存中读取的数据"""
        import struct
        
        if value_type in ["UInt8", "Int8"]:
            return struct.unpack("B" if value_type == "UInt8" else "b", data)[0]
        elif value_type in ["UInt16", "Int16"]:
            return struct.unpack("H" if value_type == "UInt16" else "h", data)[0]
        elif value_type in ["UInt32", "Int32"]:
            return struct.unpack("I" if value_type == "UInt32" else "i", data)[0]
        elif value_type in ["UInt64", "Int64"]:
            return struct.unpack("Q" if value_type == "UInt64" else "q", data)[0]
        elif value_type == "Float":
            return struct.unpack("f", data)[0]
        elif value_type == "Double":
            return struct.unpack("d", data)[0]
        elif value_type == "String":
            return data.decode('utf-8', errors='ignore').rstrip('\x00')
        elif value_type == "UTF-16 String":
            return data.decode('utf-16', errors='ignore').rstrip('\x00')
        elif value_type in ["Bytes", "Binary"]:
            return data.hex()
        else:
            raise ValueError(f"未知的值类型: {value_type}")