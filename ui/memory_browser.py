from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

class MemoryBrowser(QWidget):
    def __init__(self, memory_core, parent=None):
        super().__init__(parent)
        self.memory_core = memory_core
        self.layout = QVBoxLayout(self)
        self.history = []  # 历史记录
        self.current_index = -1  # 当前位置
        
        # 地址导航
        self.nav_layout = QHBoxLayout()
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("输入内存地址 (例如: 0x12345678)")
        self.go_btn = QPushButton("转到")
        self.back_btn = QPushButton("后退")
        self.forward_btn = QPushButton("前进")
        
        # 设置按钮状态
        self.back_btn.setEnabled(False)
        self.forward_btn.setEnabled(False)
        
        self.nav_layout.addWidget(self.back_btn)
        self.nav_layout.addWidget(self.forward_btn)
        self.nav_layout.addWidget(self.address_input)
        self.nav_layout.addWidget(self.go_btn)
        
        self.layout.addLayout(self.nav_layout)
        
        # 十六进制查看器
        self.hex_view = QHexView(self.memory_core)
        self.layout.addWidget(self.hex_view)
        
        # 数据解释器（改为浮动窗口）
        self.interpreter = DataInterpreter()
        self.interpreter_dock = QDialog(self)
        self.interpreter_dock.setWindowTitle("数据解释器")
        self.interpreter_dock.setWindowFlags(Qt.Tool | Qt.WindowStaysOnTopHint)
        dock_layout = QVBoxLayout(self.interpreter_dock)
        dock_layout.addWidget(self.interpreter)
        
        # 添加显示/隐藏解释器的按钮
        self.show_interpreter_btn = QPushButton("显示数据解释器")
        self.nav_layout.addWidget(self.show_interpreter_btn)
        
        # 连接信号
        self.go_btn.clicked.connect(self.navigate_to_input)
        self.back_btn.clicked.connect(self.navigate_back)
        self.forward_btn.clicked.connect(self.navigate_forward)
        self.address_input.returnPressed.connect(self.navigate_to_input)
        self.hex_view.selection_changed.connect(self.interpreter.update_interpretation)
        self.show_interpreter_btn.clicked.connect(self.toggle_interpreter)
        
        # 设置默认读取大小
        self.default_read_size = 1024
        
    def toggle_interpreter(self):
        """显示/隐藏数据解释器"""
        if self.interpreter_dock.isVisible():
            self.interpreter_dock.hide()
            self.show_interpreter_btn.setText("显示数据解释器")
        else:
            # 显示在主窗口右侧
            pos = self.mapToGlobal(self.rect().topRight())
            self.interpreter_dock.move(pos)
            self.interpreter_dock.show()
            self.show_interpreter_btn.setText("隐藏数据解释器")
    
    def navigate_to_input(self):
        """导航到输入的地址"""
        if not self.memory_core.script:
            QMessageBox.warning(self, "错误", "请先附加到目标进程")
            return
        
        try:
            text = self.address_input.text().strip()
            if text.startswith("0x"):
                address = int(text, 16)
            else:
                address = int(text)
            self.navigate_to_address(address)
        except ValueError:
            QMessageBox.warning(self, "错误", "请输入有效的十六进制地址")
    
    def navigate_to_address(self, address: int, size: int = None):
        """导航到指定地址"""
        if not self.memory_core.script:
            QMessageBox.warning(self, "错误", "请先附加到目标进程")
            return
        
        if isinstance(address, str):
            try:
                address = int(address, 16)
            except ValueError:
                return
        
        # 使用默认大小或指定大小
        size = size or self.default_read_size
        
        # 加载数据
        self.hex_view.load_data(address, size)
        
        # 更新地址输入框
        self.address_input.setText(f"0x{address:X}")
        
        # 添加到历史记录
        if self.current_index < len(self.history) - 1:
            # 如果不是在最后，删除当前位置之后的历史
            self.history = self.history[:self.current_index + 1]
        self.history.append(address)
        self.current_index = len(self.history) - 1
        
        # 更新导航按钮状态
        self.update_nav_buttons()
    
    def navigate_back(self):
        """后退"""
        if not self.memory_core.script:
            QMessageBox.warning(self, "错误", "请先附加到目标进程")
            return
        
        if self.current_index > 0:
            self.current_index -= 1
            address = self.history[self.current_index]
            self.hex_view.load_data(address, self.default_read_size)
            self.address_input.setText(f"0x{address:X}")
            self.update_nav_buttons()
    
    def navigate_forward(self):
        """前进"""
        if not self.memory_core.script:
            QMessageBox.warning(self, "错误", "请先附加到目标进程")
            return
        
        if self.current_index < len(self.history) - 1:
            self.current_index += 1
            address = self.history[self.current_index]
            self.hex_view.load_data(address, self.default_read_size)
            self.address_input.setText(f"0x{address:X}")
            self.update_nav_buttons()
    
    def update_nav_buttons(self):
        """更新导航按钮状态"""
        self.back_btn.setEnabled(self.current_index > 0)
        self.forward_btn.setEnabled(self.current_index < len(self.history) - 1)

class QHexView(QAbstractScrollArea):
    selection_changed = pyqtSignal(bytes)
    
    def __init__(self, memory_core, parent=None):
        super().__init__(parent)
        self.memory_core = memory_core
        self.data = bytes()
        self.base_addr = 0
        self.bytes_per_line = 16
        self.selection_start = -1
        self.selection_end = -1
        self.scroll_step = 0x50  # 滚动步长
        self.is_selecting = False  # 添加选择状态标志
        
        # 设置字体
        self.font = QFont('Courier New', 10)
        self.font_metrics = QFontMetrics(self.font)
        self.char_width = self.font_metrics.horizontalAdvance('0')
        self.char_height = self.font_metrics.height()
        
        # 计算各部分的起始位置
        self.addr_width = 16 * self.char_width  # 调整为16个字符宽度以适应64位地址
        self.hex_pos_x = self.addr_width + self.char_width * 2
        self.ascii_pos_x = self.hex_pos_x + self.bytes_per_line * 3 * self.char_width
        
        # 设置视口大小
        self.viewport().setFixedWidth(
            self.ascii_pos_x + self.bytes_per_line * self.char_width + self.char_width * 2
        )
        
        # 启用鼠标追踪
        self.setMouseTracking(True)
        
    def load_data(self, address: int, size: int):
        """加载内存数据"""
        self.data = self.memory_core.read_memory(address, size) or bytes()
        self.base_addr = address
        self.selection_start = -1
        self.selection_end = -1
        self.viewport().update()
        
    def mousePressEvent(self, event):
        """处理鼠标按下事件"""
        if not self.data:
            return
            
        pos = self._get_pos_from_point(event.pos())
        if pos >= 0:
            self.is_selecting = True  # 开始选择
            self.selection_start = pos
            self.selection_end = pos
            self.viewport().update()
    
    def mouseReleaseEvent(self, event):
        """理鼠标释放事件"""
        if not self.data or not self.is_selecting:
            return
            
        self.is_selecting = False  # 结束选择
        pos = self._get_pos_from_point(event.pos())
        if pos >= 0:
            self.selection_end = pos
            self.viewport().update()
            
            # 发送选中数据
            start = min(self.selection_start, self.selection_end)
            end = max(self.selection_start, self.selection_end) + 1
            self.selection_changed.emit(self.data[start:end])
    
    def mouseMoveEvent(self, event):
        """处理鼠标移动事件"""
        if not self.data or not self.is_selecting:  # 只在选择状态下处理
            return
            
        pos = self._get_pos_from_point(event.pos())
        if pos >= 0:
            self.selection_end = pos
            self.viewport().update()
    
    def paintEvent(self, event):
        if not self.data:
            return
            
        painter = QPainter(self.viewport())
        painter.setFont(self.font)
        
        # 计算可见行
        visible_lines = self.viewport().height() // self.char_height
        
        for row in range(visible_lines):
            offset = row * self.bytes_per_line
            if offset >= len(self.data):
                break
                
            # 绘制地址
            addr = self.base_addr + offset
            painter.drawText(2, (row + 1) * self.char_height, 
                           f"{addr:08X}")
            
            # 绘制十六进制值
            for col in range(min(self.bytes_per_line, len(self.data) - offset)):
                pos = offset + col
                x = self.hex_pos_x + col * 3 * self.char_width
                y = (row + 1) * self.char_height
                
                # 检查是否在选中范围内
                start = min(self.selection_start, self.selection_end)
                end = max(self.selection_start, self.selection_end)
                if start <= pos <= end and start != -1:
                    painter.fillRect(
                        x, y - self.char_height + 2,
                        3 * self.char_width - 2, self.char_height,
                        QColor(200, 200, 255)
                    )
                
                painter.drawText(x, y, f"{self.data[pos]:02X}")
            
            # 绘制ASCII值
            for col in range(min(self.bytes_per_line, len(self.data) - offset)):
                pos = offset + col
                x = self.ascii_pos_x + col * self.char_width
                y = (row + 1) * self.char_height
                
                # 检查是否在选中范围内
                start = min(self.selection_start, self.selection_end)
                end = max(self.selection_start, self.selection_end)
                if start <= pos <= end and start != -1:
                    painter.fillRect(
                        x, y - self.char_height + 2,
                        self.char_width, self.char_height,
                        QColor(200, 200, 255)
                    )
                
                # 显示可打印字符，否则显示点
                char = chr(self.data[pos]) if 32 <= self.data[pos] <= 126 else '.'
                painter.drawText(x, y, char)
    
    def _get_pos_from_point(self, point):
        """将鼠标坐标转换为数据位置"""
        row = point.y() // self.char_height
        col = -1
        
        # 检查是否在十六进制区域
        if self.hex_pos_x <= point.x() < self.ascii_pos_x:
            col = (point.x() - self.hex_pos_x) // (3 * self.char_width)
        # 检查是否在ASCII区域
        elif self.ascii_pos_x <= point.x():
            col = (point.x() - self.ascii_pos_x) // self.char_width
            
        if col >= 0 and col < self.bytes_per_line:
            pos = row * self.bytes_per_line + col
            if pos < len(self.data):
                return pos
        return -1
    
    def wheelEvent(self, event):
        """处理鼠标滚轮事件"""
        delta = event.angleDelta().y()
        
        if delta > 0:  # 向上滚动
            new_addr = self.base_addr - self.scroll_step
        else:  # 向下滚动
            new_addr = self.base_addr + self.scroll_step
        
        # 确保地址不为负
        if new_addr < 0:
            new_addr = 0
            
        # 重新加载数据
        self.load_data(new_addr, len(self.data))
        
        # 通知父窗口更新地址显示
        if isinstance(self.parent(), MemoryBrowser):
            self.parent().address_input.setText(f"0x{new_addr:X}")
        
        event.accept()

class DataInterpreter(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # 创建标签和值的字典
        self.value_labels = {}
        
        # 添加各种数据类型的解释
        types = {
            "b": "Int8",
            "B": "UInt8",
            "h": "Int16",
            "H": "UInt16",
            "i": "Int32",
            "I": "UInt32",
            "q": "Int64",
            "Q": "UInt64",
            "f": "Float",
            "d": "Double",
            "P": "Pointer",
            "string": "String (UTF-8)",
            "wstring": "String (UTF-16)"
        }
        
        for fmt, name in types.items():
            row = QHBoxLayout()
            row.addWidget(QLabel(f"{name}:"))
            value_label = QLabel()
            value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(value_label)
            self.value_labels[fmt] = value_label
            layout.addLayout(row)
    
    def update_interpretation(self, data: bytes):
        import struct
        
        try:
            # 基本类型解释
            formats = {
                "b": ("b", 1), "B": ("B", 1),
                "h": ("h", 2), "H": ("H", 2),
                "i": ("i", 4), "I": ("I", 4),
                "q": ("q", 8), "Q": ("Q", 8),
                "f": ("f", 4), "d": ("d", 8),
                "P": ("Q", 8)
            }
            
            for fmt, (struct_fmt, size) in formats.items():
                if len(data) >= size:
                    value = struct.unpack(struct_fmt, data[:size])[0]
                    if fmt == "P":
                        self.value_labels[fmt].setText(f"0x{value:X}")
                    else:
                        self.value_labels[fmt].setText(str(value))
                else:
                    self.value_labels[fmt].setText("N/A")
            
            # 字符串解释
            try:
                if data:
                    self.value_labels["string"].setText(data.decode('utf-8'))
                else:
                    self.value_labels["string"].setText("N/A")
            except:
                self.value_labels["string"].setText("Invalid UTF-8")
                
            try:
                if len(data) >= 2:
                    self.value_labels["wstring"].setText(data.decode('utf-16'))
                else:
                    self.value_labels["wstring"].setText("N/A")
            except:
                self.value_labels["wstring"].setText("Invalid UTF-16")
                
        except Exception as e:
            print(f"解释错误: {str(e)}") 