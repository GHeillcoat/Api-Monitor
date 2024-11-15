import frida
from core.logger import logger

class HookCore:
    def __init__(self):
        self.session = None
        self.scripts = {}  # 存储每个Hook的script对象
        logger.info("Hook核心初始化完成")
        
    def attach_process(self, pid):
        try:
            logger.info(f"[HookCore] 开始附加到进程 {pid}")
            logger.debug(f"[HookCore] 当前session状态: {self.session}")
            
            # 移除 timeout 参数
            logger.debug("[HookCore] 正在调用frida.attach...")
            self.session = frida.attach(pid)  # 移除 timeout 参数
            logger.info(f"[HookCore] 成功附加到进程 {pid}")
            
        except frida.ProcessNotFoundError:
            logger.error(f"[HookCore] 进程未找到: {pid}")
            raise Exception("进程未找到")
        except frida.PermissionDeniedError:
            logger.error(f"[HookCore] 权限不足，无法附加到进程 {pid}")
            raise Exception("权限不足")
        except frida.ServerNotRunningError:
            logger.error("[HookCore] Frida server 未运行")
            raise Exception("Frida server 未运行")
        except Exception as e:
            logger.error(f"[HookCore] 附加进程时发生未知错误: {str(e)}")
            raise
    
    def hook_function(self, module_name, function_name, params, hook_id=None):
        script_template = """
        var baseAddr = Module.findBaseAddress('{module}');
        var targetAddr = Module.findExportByName('{module}', '{function}');
        if (targetAddr === null) {{
            throw new Error('找不到函数: {module}!{function}');
        }}
        
        send('[DEBUG] 找到函数 {module}!{function} 地址: ' + targetAddr);
        
        Interceptor.attach(targetAddr, {{
            onEnter: function(args) {{
                // 收集参数信息
                var params = [];
                {param_loggers}
                
                // 收集调用堆栈
                var stack = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .filter(x => x.toString().indexOf('(null)') === -1)
                    .join('\\n');
                
                // 发送格式化的日志
                send('[DEBUG] ----------------------------------------');
                send('[DEBUG] 函数调用: {module}!{function}');
                send('[DEBUG] ----------------------------------------');
                
                // 发送参数信息
                for (let param of params) {{
                    send('[DEBUG] ' + param.name + ': ' + param.value);
                }}
                
                // 发送调用堆栈
                if (stack) {{
                    send('[DEBUG] ----------------------------------------');
                    send('[DEBUG] 调用堆栈:\\n' + stack);
                    send('[DEBUG] ----------------------------------------');
                }}
            }},
            onLeave: function(retval) {{
                send('[DEBUG] 返回值: ' + retval);
                send('[DEBUG] ========================================\\n');
            }}
        }});
        """
        
        # 生成参数日志代码
        param_loggers = []
        for i, (alias, param_type) in enumerate(params):
            logger_code = self._get_param_logger(i, param_type)
            param_loggers.append(
                f"try {{ params.push({{ name: '{alias}', value: {logger_code} }}); }} "
                f"catch(e) {{ params.push({{ name: '{alias}', value: '<error: ' + e.message + '>' }}); }}"
            )
        
        script_code = script_template.format(
            module=module_name,
            function=function_name,
            param_loggers='\n                '.join(param_loggers)
        )
        
        if self.session:
            try:
                script = self.session.create_script(script_code)
                script.on('message', self._on_message)
                script.load()
                if hook_id is not None:
                    self.scripts[hook_id] = script
                else:
                    self.script = script  # 保持向后兼容
                logger.info(f"成功Hook函数: {module_name}!{function_name}")
            except Exception as e:
                logger.error(f"Hook函数失败: {str(e)}")
                raise
    
    def hook_custom_address(self, base_addr, offset, args_count, params, hook_id=None):
        script_template = """
        var targetAddr = ptr('{base}').add({offset});
        Interceptor.attach(targetAddr, {{
            onEnter: function(args) {{
                var params = [];
                for(var i = 0; i < {args_count}; i++) {{
                    {param_logger}
                }}
                send('[DEBUG] Hook at {base}+{offset}\\n参数: ' + params.join('\\n'));
            }},
            onLeave: function(retval) {{
                send('[DEBUG] 返回值: ' + retval);
                send('[DEBUG] ------------------------');
            }}
        }});
        """
        
        param_logger = self._get_param_logger(params[0][1])
        
        script_code = script_template.format(
            base=base_addr,
            offset=offset,
            args_count=args_count,
            param_logger=param_logger
        )
        
        if self.session:
            script = self.session.create_script(script_code)
            script.on('message', self._on_message)
            script.load()
            if hook_id is not None:
                self.scripts[hook_id] = script
            else:
                self.script = script  # 保持向后兼容
    
    def _get_param_logger(self, index, param_type):
        """根据参数类型返回相应的日志代码"""
        type_map = {
            "整数(int)": f"args[{index}].toInt32()",
            "整数(uint)": f"args[{index}].toUInt32()",
            "长整数(int64)": f"args[{index}].toString()",
            "浮点(float)": f"args[{index}].readFloat()",
            "双精度(double)": f"args[{index}].readDouble()",
            "指针(ptr)": f"args[{index}]",
            "字符串(ascii)": f"args[{index}].readCString()",
            "字符串(unicode)": f"args[{index}].readUtf16String()",
            "字节数组(bytes)": f"hexdump(args[{index}], {{length: 16, header: true}})",
            "句柄(HWND)": f"args[{index}]",
        }

        # 特殊处理 MessageBoxA/W 的参数
        if index == 0:  # hWnd
            return f"args[{index}]"
        elif index in [1, 2]:  # lpText, lpCaption
            return f"args[{index}].readCString()"  # MessageBoxA 用 readCString
        elif index == 3:  # uType
            return f"args[{index}].toUInt32()"
        
        return type_map.get(param_type, f"args[{index}]")
    
    def _on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            if payload.startswith('[DEBUG]'):
                content = payload[7:].strip()
                
                # 直接输出调试信息
                if '=========' in content:  # 分隔符
                    logger.debug('----------------------------------------')
                elif '函数调用:' in content:
                    logger.debug(f'函数调用: {content.split("函数调用:", 1)[1].strip()}')
                elif ': ' in content and not '调用堆栈:' in content:  # 参数信息
                    logger.debug(content)
                elif '调用堆栈:' in content:
                    # 修改堆栈处理逻辑
                    if '\n' in content:  # 注意这里改为 \n 而不是 \\n
                        stack_parts = content.split('\n', 1)
                        logger.debug('调用堆栈:')
                        if len(stack_parts) > 1:
                            stack = stack_parts[1]
                            for line in stack.split('\n'):
                                if line.strip():  # 只输出非空行
                                    logger.debug(f'  {line.strip()}')
                elif '返回值:' in content:
                    logger.debug(f'返回值: {content.split("返回值:", 1)[1].strip()}')
                else:
                    logger.debug(content)
        elif message['type'] == 'error':
            logger.error(f'Hook错误: {message["stack"]}')
    
    def disable_hook(self, hook_id):
        """停用指定的Hook"""
        try:
            if hook_id in self.scripts:
                script = self.scripts[hook_id]
                script.unload()  # 卸载script
                del self.scripts[hook_id]
                logger.info(f"成功停用Hook {hook_id}")
            else:
                logger.warning(f"未找到Hook {hook_id}")
        except Exception as e:
            logger.error(f"停用Hook失败: {str(e)}")
            raise