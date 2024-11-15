from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                           QComboBox, QSplitter, QMessageBox, QFileDialog)
from PyQt5.QtCore import Qt, QDir
from PyQt5.QtGui import QColor, QFont, QKeySequence
from PyQt5.Qsci import QsciScintilla, QsciLexerJavaScript, QsciAPIs
from PyQt5.QtWidgets import QShortcut
import json
import os
from core.logger import logger

class FridaScriptEditor(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.hook_core = None
        self.output_window = None
        self.current_file = None  # 当前文件路径
        self.setup_shortcuts()  # 设置快捷键
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # 工具栏
        toolbar = QHBoxLayout()
        
        # 示例代码下拉框
        self.example_combo = QComboBox()
        self.example_combo.addItem("选择示例代码...")
        self.example_combo.currentIndexChanged.connect(self.load_example)
        
        # 保存按钮
        self.save_btn = QPushButton("保存")
        self.save_btn.clicked.connect(self.save_script)
        
        # 运行按钮
        self.run_btn = QPushButton("运行")
        self.run_btn.clicked.connect(self.run_script)
        
        toolbar.addWidget(self.example_combo)
        toolbar.addWidget(self.save_btn)
        toolbar.addWidget(self.run_btn)
        toolbar.addStretch()
        
        layout.addLayout(toolbar)
        
        # 创建编辑器
        self.editor = QsciScintilla()
        self.setup_editor()
        
        layout.addWidget(self.editor)
        
        # 加载示例代码
        self.load_examples()
        
        # 创建脚本目录
        self.scripts_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts')
        if not os.path.exists(self.scripts_dir):
            os.makedirs(self.scripts_dir)
    
    def setup_shortcuts(self):
        # Ctrl+S 保存
        self.save_shortcut = QShortcut(QKeySequence("Ctrl+S"), self)
        self.save_shortcut.activated.connect(self.save_script)
        
        # Ctrl+Shift+S 另存为
        self.save_as_shortcut = QShortcut(QKeySequence("Ctrl+Shift+S"), self)
        self.save_as_shortcut.activated.connect(lambda: self.save_script(save_as=True))
        
        # F5 运行
        self.run_shortcut = QShortcut(QKeySequence("F5"), self)
        self.run_shortcut.activated.connect(self.run_script)
    
    def save_script(self, save_as=False):
        """保存脚本"""
        if not self.current_file or save_as:
            # 打开文件对话框
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "保存脚本",
                self.scripts_dir,
                "JavaScript Files (*.js);;All Files (*)"
            )
            if not file_path:
                return
            self.current_file = file_path
        
        try:
            # 保存文件
            with open(self.current_file, 'w', encoding='utf-8') as f:
                f.write(self.editor.text())
            
            # 更新窗口标题
            if self.window():
                current_title = self.window().windowTitle()
                if ' - ' in current_title:
                    base_title = current_title.split(' - ')[0]
                else:
                    base_title = current_title
                self.window().setWindowTitle(f"{base_title} - {os.path.basename(self.current_file)}")
            
            logger.info(f"脚本已保存到: {self.current_file}")
            self.status_message("保存成功")
        except Exception as e:
            logger.error(f"保存脚本失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"保存失败: {str(e)}")
    
    def load_script(self, file_path):
        """加载脚本文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.editor.setText(f.read())
            self.current_file = file_path
            logger.info(f"已加载脚本: {file_path}")
        except Exception as e:
            logger.error(f"加载脚本失败: {str(e)}")
            QMessageBox.warning(self, "错误", f"加载失败: {str(e)}")
    
    def run_script(self):
        """运行脚本"""
        # 如果有未保存的更改，先保存
        if self.editor.isModified() and self.current_file:
            self.save_script()
        
        try:
            script_text = self.editor.text()
            if not script_text.strip():
                QMessageBox.warning(self, "错误", "脚本内容不能为空")
                return
            
            if not self.hook_core or not self.hook_core.session:
                QMessageBox.warning(self, "错误", "请先附加到目标进程")
                return
            
            # 创建输出窗口
            if not self.output_window:
                from .script_output import ScriptOutputWindow
                self.output_window = ScriptOutputWindow()
            self.output_window.show()
            
            # 创建并加载脚本
            script = self.hook_core.session.create_script(script_text)
            script.on('message', self._on_message)
            script.load()
            
            # 保存脚本引用
            self.current_script = script
            
            logger.info("脚本加载成功")
            self.output_window.append_message("脚本已加载并开始运行", 'info')
            
        except Exception as e:
            logger.error(f"运行脚本失败: {str(e)}")
            if self.output_window:
                self.output_window.append_message(f"运行脚本失败: {str(e)}", 'error')
            QMessageBox.warning(self, "错误", f"运行脚本失败: {str(e)}")
    
    def status_message(self, message):
        """显示状态栏消息"""
        if self.window() and hasattr(self.window(), 'status_bar'):
            self.window().status_bar.showMessage(message, 3000)  # 显示3秒
        
    def setup_editor(self):
        # 设置字体
        font = QFont("Consolas", 11)
        self.editor.setFont(font)
        
        # 设置JavaScript语法高亮
        self.lexer = QsciLexerJavaScript()  # 保存为实例变量
        self.lexer.setFont(font)
        
        # 设置VSCode风格的颜色
        self.lexer.setColor(QColor("#D4D4D4"), QsciLexerJavaScript.Default)  # 默认文本
        self.lexer.setColor(QColor("#569CD6"), QsciLexerJavaScript.Keyword)  # 关键字
        self.lexer.setColor(QColor("#CE9178"), QsciLexerJavaScript.DoubleQuotedString)  # 字符串
        self.lexer.setColor(QColor("#608B4E"), QsciLexerJavaScript.Comment)  # 注释
        self.lexer.setColor(QColor("#9CDCFE"), QsciLexerJavaScript.Identifier)  # 标识符
        self.lexer.setColor(QColor("#B5CEA8"), QsciLexerJavaScript.Number)  # 数字
        self.lexer.setColor(QColor("#C586C0"), QsciLexerJavaScript.Operator)  # 运算符
        
        # 设置所有样式的背景色
        for style in range(128):  # 为所有可能的样式设置背景色
            self.lexer.setPaper(QColor("#1E1E1E"), style)
            self.lexer.setFont(font, style)
        
        # 设置编辑器背景色和前景色
        self.editor.setColor(QColor("#D4D4D4"))  # 文本颜色
        self.editor.setPaper(QColor("#1E1E1E"))  # 背景色
        
        # 设置lexer
        self.editor.setLexer(self.lexer)
        
        # JavaScript 关键词列表
        js_keywords = [
            # JavaScript 关键字
            'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 
            'default', 'delete', 'do', 'else', 'export', 'extends', 'false', 
            'finally', 'for', 'function', 'if', 'import', 'in', 'instanceof', 
            'new', 'null', 'return', 'super', 'switch', 'this', 'throw', 'true', 
            'try', 'typeof', 'var', 'void', 'while', 'with', 'yield', 'let', 'await',
            'async', 'static',
            
            # Frida API - 核心对象
            'Interceptor', 'Process', 'Module', 'Memory', 'Thread', 'NativeFunction',
            'NativeCallback', 'File', 'Socket', 'Console', 'Java', 'ObjC', 'send', 
            'recv', 'rpc', 'hexdump', 'int64', 'uint64', 'ptr', 'NULL', 'console',
            
            # Console 方法
            'console.log', 'console.warn', 'console.error', 'console.debug', 
            'console.time', 'console.timeEnd', 'console.trace',
            
            # Memory 方法
            'Memory.alloc', 'Memory.copy', 'Memory.dup', 'Memory.protect',
            'Memory.scan', 'Memory.scanSync', 'Memory.readPointer', 'Memory.readS8',
            'Memory.readU8', 'Memory.readS16', 'Memory.readU16', 'Memory.readS32',
            'Memory.readU32', 'Memory.readS64', 'Memory.readU64', 'Memory.readFloat',
            'Memory.readDouble', 'Memory.readByteArray', 'Memory.readCString',
            'Memory.readUtf8String', 'Memory.readUtf16String', 'Memory.readAnsiString',
            'Memory.writePointer', 'Memory.writeS8', 'Memory.writeU8', 'Memory.writeS16',
            'Memory.writeU16', 'Memory.writeS32', 'Memory.writeU32', 'Memory.writeS64',
            'Memory.writeU64', 'Memory.writeFloat', 'Memory.writeDouble',
            'Memory.writeByteArray', 'Memory.writeCString', 'Memory.writeUtf8String',
            'Memory.writeUtf16String', 'Memory.writeAnsiString',
            
            # Process 方法
            'Process.id', 'Process.arch', 'Process.platform', 'Process.pageSize',
            'Process.pointerSize', 'Process.getCurrentThreadId', 'Process.enumerateModules',
            'Process.enumerateThreads', 'Process.enumerateMallocRanges', 'Process.setExceptionHandler',
            
            # Module 方法
            'Module.load', 'Module.ensureInitialized', 'Module.findBaseAddress',
            'Module.findExportByName', 'Module.getBaseAddress', 'Module.getExportByName',
            'Module.getFileName', 'Module.getImportByName', 'Module.enumerateExports',
            'Module.enumerateImports', 'Module.enumerateSymbols', 'Module.enumerateRanges',
            
            # Interceptor 方法
            'Interceptor.attach', 'Interceptor.detach', 'Interceptor.replace',
            'Interceptor.revert', 'Interceptor.flush', 'onEnter', 'onLeave',
            'this.context', 'this.returnAddress', 'this.threadId', 'this.depth',
            'this.errno', 'backtrace', 'backtraceHere', 'printStackTrace',
            
            # Thread 方法
            'Thread.backtrace', 'Thread.sleep', 'Thread.getCurrentThreadId',
            
            # 常用属性和方法
            'length', 'toString', 'valueOf', 'prototype', 'constructor', 'arguments',
            'call', 'apply', 'bind', 'map', 'filter', 'reduce', 'forEach', 'some',
            'every', 'indexOf', 'lastIndexOf', 'slice', 'splice', 'concat', 'join',
            'push', 'pop', 'shift', 'unshift', 'sort', 'reverse',
            
            # 数据类型和工具
            'ArrayBuffer', 'Int8Array', 'Uint8Array', 'Int16Array', 'Uint16Array',
            'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array', 'NativePointer',
            'Int64', 'UInt64', 'ByteArray', 'ApiResolver', 'DebugSymbol', 'Instruction',
            'X86Writer', 'X86Relocator', 'ArmWriter', 'ArmRelocator', 'ThumbWriter',
            'ThumbRelocator'

            # frida方法
            "Frida","Frida.version","Frida.heapSize"
        ]
        
        # 创建 APIs
        self.apis = QsciAPIs(self.lexer)
        for keyword in js_keywords:
            self.apis.add(keyword)
        self.apis.prepare()
        
        # 设置自动补全
        self.editor.setAutoCompletionSource(QsciScintilla.AcsAll)
        self.editor.setAutoCompletionThreshold(2)
        self.editor.setAutoCompletionCaseSensitivity(False)
        self.editor.setAutoCompletionReplaceWord(True)
        
        # 显示行号
        self.editor.setMarginType(0, QsciScintilla.NumberMargin)
        self.editor.setMarginWidth(0, "000")
        
        # 代码折叠设置
        self.editor.setFolding(QsciScintilla.BoxedTreeFoldStyle)
        self.editor.setFoldMarginColors(QColor("#1E1E1E"), QColor("#1E1E1E"))
        
        # 设置折叠线的颜色
        self.editor.SendScintilla(QsciScintilla.SCI_SETFOLDMARGINCOLOUR, True, QColor("#1E1E1E"))
        self.editor.SendScintilla(QsciScintilla.SCI_SETFOLDMARGINHICOLOUR, True, QColor("#1E1E1E"))
        
        # 设置折叠标记的颜色
        for marker in [
            QsciScintilla.SC_MARKNUM_FOLDEROPEN,
            QsciScintilla.SC_MARKNUM_FOLDER,
            QsciScintilla.SC_MARKNUM_FOLDERSUB,
            QsciScintilla.SC_MARKNUM_FOLDERTAIL,
            QsciScintilla.SC_MARKNUM_FOLDEREND,
            QsciScintilla.SC_MARKNUM_FOLDEROPENMID,
            QsciScintilla.SC_MARKNUM_FOLDERMIDTAIL
        ]:
            self.editor.SendScintilla(QsciScintilla.SCI_MARKERSETFORE, marker, QColor("#4EC9B0"))
            self.editor.SendScintilla(QsciScintilla.SCI_MARKERSETBACK, marker, QColor("#1E1E1E"))
        
        # 设置折叠线的样式
        self.editor.SendScintilla(QsciScintilla.SCI_SETFOLDFLAGS, 16)
        
        # 设置代码折叠线的颜色
        self.editor.SendScintilla(QsciScintilla.SCI_STYLESETFORE, QsciScintilla.STYLE_LINENUMBER, QColor("#4EC9B0"))
        
        # 设置缩进指南的颜色
        self.editor.setIndentationGuides(True)
        self.editor.setIndentationGuidesBackgroundColor(QColor("#1E1E1E"))
        self.editor.setIndentationGuidesForegroundColor(QColor("#4EC9B0"))
        
        # 设置所有可能的折叠相关样式
        for style in [
            QsciScintilla.STYLE_DEFAULT,
            QsciScintilla.STYLE_LINENUMBER,
            QsciScintilla.STYLE_INDENTGUIDE,
            QsciScintilla.STYLE_BRACELIGHT
        ]:
            self.editor.SendScintilla(QsciScintilla.SCI_STYLESETFORE, style, QColor("#4EC9B0"))
        
        # 当前行高亮
        self.editor.setCaretLineVisible(True)
        self.editor.setCaretLineBackgroundColor(QColor("#282828"))
        self.editor.setCaretForegroundColor(QColor("#FFFFFF"))  # 光标颜色
        
        # 缩进设置
        self.editor.setIndentationsUseTabs(False)
        self.editor.setTabWidth(4)
        self.editor.setIndentationGuides(True)
        self.editor.setIndentationGuidesBackgroundColor(QColor("#2D2D2D"))
        self.editor.setIndentationGuidesForegroundColor(QColor("#404040"))
        
        # 括号匹配
        self.editor.setBraceMatching(QsciScintilla.SloppyBraceMatch)
        self.editor.setMatchedBraceBackgroundColor(QColor("#264F78"))
        self.editor.setMatchedBraceForegroundColor(QColor("#FFFFFF"))
        
        # 选择区域
        self.editor.setSelectionBackgroundColor(QColor("#264F78"))
        self.editor.setSelectionForegroundColor(QColor("#FFFFFF"))
        
        # 设置边缘线
        self.editor.setEdgeMode(QsciScintilla.EdgeLine)
        self.editor.setEdgeColumn(80)
        self.editor.setEdgeColor(QColor("#404040"))
    
    def load_examples(self):
        examples = {
            "基础Hook示例": """// 基础Hook示例
var messageBoxW = Module.findExportByName(null, 'MessageBoxW');
if (messageBoxW) {
    Interceptor.attach(messageBoxW, {
        onEnter: function(args) {
            send('[DEBUG] MessageBoxW被调用');
            send('[DEBUG] 文本内容: ' + args[1].readUtf16String());
            send('[DEBUG] 标题: ' + args[2].readUtf16String());
        }
    });
    // 保持脚本运行
    setInterval(function() {}, 1000);
}""",
            "内存监控示例": """// 内存监控示例
var baseAddr = Process.enumerateModules()[0].base;
var size = 0x1000;

Memory.protect(baseAddr, size, 'rwx');

Interceptor.attach(ptr(baseAddr), {
    onEnter: function(args) {
        send('[DEBUG] 内存访问: ' + this.context.pc);
    }
});

// 保持脚本运行
setInterval(function() {}, 1000);
""",
            "函数调用追踪": """// 函数调用追踪示例
var targetModule = Process.enumerateModules()[0];

Interceptor.attach(targetModule.base, {
    onEnter: function(args) {
        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress);
        send('[DEBUG] 调用堆栈:\\n' + backtrace.join('\\n'));
    }
});

// 保持脚本运行
setInterval(function() {}, 1000);
""",
            "API监控模板": """// API监控模板
'use strict';

// 保存所有的 hook 句柄
var hooks = [];

// Hook指定函数
function hookFunction(moduleName, functionName) {
    var exportAddr = Module.findExportByName(moduleName, functionName);
    if (exportAddr) {
        var hook = Interceptor.attach(exportAddr, {
            onEnter: function(args) {
                send(`[DEBUG] ${moduleName}!${functionName} 被调用`);
                // 这里添加参数处理逻辑
            },
            onLeave: function(retval) {
                send(`[DEBUG] ${moduleName}!${functionName} 返回: ${retval}`);
            }
        });
        hooks.push(hook);
        send(`[DEBUG] 成功Hook ${moduleName}!${functionName}`);
    }
}

// 添加要监控的函数
hookFunction('user32.dll', 'MessageBoxW');
hookFunction('kernel32.dll', 'CreateFileW');
// 添加更多函数...

// 保持脚本运行
setInterval(function() {}, 1000);

// 清理函数 (可选)
function cleanup() {
    hooks.forEach(hook => hook.detach());
    hooks = [];
}
""",
            "内存写入监控": """// 监控内存写入
function watchMemoryWrite(address, size) {
    const thread = Process.enumerateThreads()[0];
    
    Process.setExceptionHandler(e => {
        send('[DEBUG] ===== 检测到内存写入 =====');
        send('[DEBUG] 地址: ' + e.context.pc);
        
        // 获取调用堆栈
        const backtrace = Thread.backtrace(e.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .filter(addr => addr.toString().indexOf('(null)') === -1);
            
        send('[DEBUG] 调用堆栈:\\n' + backtrace.join('\\n'));
        
        if (Process.getCurrentThreadId() === thread.id &&
            ['breakpoint', 'single-step'].includes(e.type)) {
            thread.unsetHardwareWatchpoint(0);
            send('[DEBUG] 已禁用硬件监视点');
            return true;
        }
        
        send('[DEBUG] 传递给应用程序');
        return false;
    });
    
    thread.setHardwareWatchpoint(0, ptr(address), size, 'w');  // 'w' 表示监控写入
    send('[DEBUG] 内存写入监控已启动');
    
    // 保持脚本运行
    setInterval(() => {}, 1000);
}

// 使用示例：监控指定地址的4字节写入
// watchMemoryWrite('0x12345678', 4);
""",
            "内存访问监控": """// 监控内存访问
function watchMemoryAccess(address, size) {
    const thread = Process.enumerateThreads()[0];
    
    Process.setExceptionHandler(e => {
        send('[DEBUG] ===== 检测到内存访问 =====');
        send('[DEBUG] 地址: ' + e.context.pc);
        send('[DEBUG] 访问类型: ' + e.type);
        
        // 获取寄存器状态
        const context = JSON.stringify(e.context, null, 2);
        send('[DEBUG] 寄存器状态:\\n' + context);
        
        // 获取调用堆栈
        const backtrace = Thread.backtrace(e.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .filter(addr => addr.toString().indexOf('(null)') === -1);
            
        send('[DEBUG] 调用堆栈:\\n' + backtrace.join('\\n'));
        
        if (Process.getCurrentThreadId() === thread.id &&
            ['breakpoint', 'single-step'].includes(e.type)) {
            thread.unsetHardwareWatchpoint(0);
            send('[DEBUG] 已禁用硬件监视点');
            return true;
        }
        
        send('[DEBUG] 传递给应用程序');
        return false;
    });
    
    thread.setHardwareWatchpoint(0, ptr(address), size, 'rw');  // 'rw' 表示监控读写
    send('[DEBUG] 内存访问监控已启动');
    
    // 保持脚本运行
    setInterval(() => {}, 1000);
}

// 使用示例：监控指定地址的4字节读写访问
// watchMemoryAccess('0x12345678', 4);
""",
            "内存断点监控": """// 内存断点监控
function setMemoryBreakpoint(address, size, options = { onRead: true, onWrite: true }) {
    const thread = Process.enumerateThreads()[0];
    let conditions = '';
    
    if (options.onRead && options.onWrite) {
        conditions = 'rw';
    } else if (options.onRead) {
        conditions = 'r';
    } else if (options.onWrite) {
        conditions = 'w';
    }
    
    Process.setExceptionHandler(e => {
        const operation = e.type === 'breakpoint' ? '读取' : '写入';
        send('[DEBUG] ===== 检测到内存' + operation + ' =====');
        send('[DEBUG] 操作地址: ' + e.context.pc);
        send('[DEBUG] 线程ID: ' + Process.getCurrentThreadId());
        
        // 获取模块信息
        const moduleMap = new ModuleMap();
        const moduleDetails = moduleMap.find(e.context.pc);
        if (moduleDetails) {
            send('[DEBUG] 所属模块: ' + moduleDetails.name + ' (基址: ' + moduleDetails.base + ')');
        }
        
        // 获取调用堆栈
        const backtrace = Thread.backtrace(e.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .filter(addr => addr.toString().indexOf('(null)') === -1);
            
        send('[DEBUG] 调用堆栈:\\n' + backtrace.join('\\n'));
        
        if (Process.getCurrentThreadId() === thread.id &&
            ['breakpoint', 'single-step'].includes(e.type)) {
            thread.unsetHardwareWatchpoint(0);
            send('[DEBUG] 已禁用硬件监视点');
            return true;
        }
        
        send('[DEBUG] 传递给应用程序');
        return false;
    });
    
    thread.setHardwareWatchpoint(0, ptr(address), size, conditions);
    send('[DEBUG] 内存断点监控已启动');
    send('[DEBUG] 监控地址: ' + address);
    send('[DEBUG] 监控大小: ' + size + ' 字节');
    send('[DEBUG] 监控类型: ' + (conditions === 'rw' ? '读写' : conditions === 'r' ? '只读' : '只写'));
    
    // 保持脚本运行
    setInterval(() => {}, 1000);
}

// 使用示例：
// setMemoryBreakpoint('0x12345678', 4, { onRead: true, onWrite: true });  // 监控读写
// setMemoryBreakpoint('0x12345678', 4, { onRead: true, onWrite: false }); // 只监控读
// setMemoryBreakpoint('0x12345678', 4, { onRead: false, onWrite: true }); // 只监控写
"""
        }
        
        self.example_combo.addItems(examples.keys())
        self.examples = examples
        
    def load_example(self, index):
        if index <= 0:
            return
            
        example_name = self.example_combo.currentText()
        if example_name in self.examples:
            self.editor.setText(self.examples[example_name])
            
    def set_hook_core(self, hook_core):
        """设置 HookCore 实例"""
        self.hook_core = hook_core

    def _on_message(self, message, data):
        """处理脚本消息"""
        if not self.output_window:
            return
        
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, str):
                if payload.startswith('[DEBUG]'):
                    level = 'debug'
                    text = payload[7:].strip()
                else:
                    level = 'default'
                    text = payload
                
                if '=========' in text:
                    self.output_window.append_message('----------------------------------------', 'separator')
                elif '函数调用:' in text:
                    self.output_window.append_message(f'函数调用: {text.split("函数调用:", 1)[1].strip()}', 'info')
                elif ': ' in text and not '调用堆栈:' in text:
                    self.output_window.append_message(text, level)
                elif '调用堆栈:' in text:
                    if '\n' in text:
                        stack_parts = text.split('\n', 1)
                        self.output_window.append_message('调用堆栈:', level)
                        if len(stack_parts) > 1:
                            stack = stack_parts[1]
                            for line in stack.split('\n'):
                                if line.strip():
                                    self.output_window.append_message(f'  {line.strip()}', 'debug')
                elif '返回值:' in text:
                    self.output_window.append_message(f'返回值: {text.split("返回值:", 1)[1].strip()}', 'info')
                else:
                    self.output_window.append_message(text, level)
                
        elif message['type'] == 'error':
            self.output_window.append_message(f"脚本错误: {message['description']}", 'error') 