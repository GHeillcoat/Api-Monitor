import frida
from core.logger import logger
from typing import List, Tuple, Optional, Any
import os
import concurrent.futures
import psutil

class MemoryCore:
    def __init__(self, device_id=None):
        self.session = None
        self.script = None
        self.process_id = None
        self.device = self._get_device(device_id)
        
    def _get_device(self, device_id):
        """获取设备"""
        try:
            if device_id:
                return frida.get_device(device_id)
            else:
                return frida.get_local_device()  # 使用本地设备
        except Exception as e:
            logger.error(f"获取设备失败: {str(e)}")
            raise Exception("获取设备失败")
        
    def _check_process(self, pid):
        """检查进程状态"""
        try:
            process = psutil.Process(pid)
            logger.debug(f"[MemoryCore] 进程状态:")
            logger.debug(f"  名称: {process.name()}")
            logger.debug(f"  状态: {process.status()}")
            logger.debug(f"  创建时间: {process.create_time()}")
            logger.debug(f"  CPU使用率: {process.cpu_percent()}%")
            logger.debug(f"  内存使用: {process.memory_info().rss / 1024 / 1024:.2f} MB")
            return True
        except Exception as e:
            logger.warning(f"[MemoryCore] 无法获取进程状态: {str(e)}")
            return False
        
    def attach_process(self, pid):
        """附加到指定进程"""
        try:
            logger.info(f"[MemoryCore] 开始附加到进程 {pid}")
            
            # 添加进程状态检查
            self._check_process(pid)
            
            logger.debug(f"[MemoryCore] Frida 版本: {frida.__version__}")
            logger.debug(f"[MemoryCore] 进程 ID: {pid}")
            
            if self.session:
                logger.debug("[MemoryCore] 清理现有session...")
                self.cleanup()
            
            # 尝试获取进程信息
            try:
                process = self.device.get_frontmost_application()
                if process:
                    logger.debug(f"[MemoryCore] 当前前台进程: {process.name} (PID: {process.pid})")
            except Exception as e:
                logger.warning(f"[MemoryCore] 无法获取进程信息: {str(e)}")
            
            logger.debug("[MemoryCore] 正在调用 frida.attach...")
            self.session = frida.attach(pid)
            
            logger.debug("[MemoryCore] 正在加载内存脚本...")
            self._load_memory_script()
            logger.info(f"[MemoryCore] 成功附加到进程 {pid}")
            
        except frida.ProcessNotFoundError:
            logger.error(f"[MemoryCore] 进程未找到: {pid}")
            raise Exception("进程未找到")
        except frida.PermissionDeniedError:
            logger.error(f"[MemoryCore] 权限不足，无法附加到进程 {pid}")
            raise Exception("权限不足")
        except frida.ServerNotRunningError:
            logger.error("[MemoryCore] Frida server 未运行")
            raise Exception("Frida server 未运行")
        except Exception as e:
            logger.error(f"[MemoryCore] 附加进程时发生未知错误: {str(e)}")
            logger.error(f"[MemoryCore] 错误类型: {type(e).__name__}")
            self.cleanup()
            raise Exception(f"附加失败: {str(e)}")
    
    def cleanup(self):
        """清理资源"""
        try:
            if self.script:
                self.script.unload()
                self.script = None
            if self.session:
                self.session.detach()
                self.session = None
            self.process_id = None
        except Exception as e:
            logger.error(f"清理资源失败: {str(e)}")
    
    def _load_memory_script(self):
        """加载内存操作脚本"""
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(os.path.dirname(current_dir), 'scripts', 'memory_scan.js')
            
            with open(script_path, 'r', encoding='utf-8') as f:
                script_code = f.read()
            
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            
        except Exception as e:
            logger.error(f"脚本加载失败: {str(e)}")
            self.cleanup()
            raise Exception(f"脚本加载失败: {str(e)}")
    
    def _on_message(self, message, data):
        """处理来自JS的消息"""
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict) and payload.get('type') == 'progress':
                if hasattr(self, 'progress_callback'):
                    self.progress_callback(payload['progress'])
            else:
                logger.debug(f"JS消息: {message}")
        elif message['type'] == 'error':
            logger.error(f"JS错误: {message['description']}")
    
    def scan_memory(self, value_type: str, value: str, page_size: int = 0x1000, thread_count: int = 4) -> list:
        """扫描内存"""
        try:
            if not self.script:
                raise Exception("未附加到进程")
            
            # 根据value_type确定byte_length和处理输入值
            type_sizes = {
                "UInt8": 1, "Int8": 1,
                "UInt16": 2, "Int16": 2,
                "UInt32": 4, "Int32": 4, "4字节": 4,
                "UInt64": 8, "Int64": 8, "8字节": 8,
                "Float": 4,
                "Double": 8,
                "String": None
            }
            
            byte_length = type_sizes.get(value_type, 4)
            
            # 处理输入值
            try:
                if value_type in ["Float", "Double"]:
                    processed_value = str(float(value))
                elif value_type == "String":
                    processed_value = str(value)
                else:
                    processed_value = str(int(value))
            except ValueError:
                logger.error(f"输入值格式错误: {value}")
                return []
            
            try:
                count = self.script.exports.newscanbyprotect(
                    'rw-',  # 扫描读写区域
                    processed_value,  # 使用处理后的值
                    byte_length
                )
                
                if count > 0:
                    results = self.script.exports.getscanresults()
                    return results
                return []
                
            except Exception as e:
                logger.error(f"扫描内存失败: {str(e)}")
                return []
                
        except Exception as e:
            logger.error(f"内存扫描失败: {str(e)}")
            return []
    
    def next_scan(self, scan_type: str, value: str = None) -> list:
        """下一轮扫描"""
        try:
            if not self.script:
                raise Exception("未附加到进程")
            
            # 处理特殊的扫描类型
            if scan_type in ['4字节', '8字节']:
                return self.scan_memory(scan_type, value)
            
            # 使用小写的函数映射
            scan_functions = {
                'equal': 'nextscanequal',
                'unchange': 'nextscanunchange',
                'change': 'nextscanchange',
                'bigger': 'nextscanlarger',
                'smaller': 'nextscanlittler',
                'increase': 'nextscanincrease',
                'decrease': 'nextscandecrease'
            }
            
            func_name = scan_functions.get(scan_type)
            if not func_name:
                raise Exception(f"未知的扫描类型: {scan_type}")
            
            count = self.script.exports[func_name](value)
            if count > 0:
                results = self.script.exports.getscanresults()
                return results
            return []
            
        except Exception as e:
            logger.error(f"内存扫描失败: {str(e)}")
            return []
    
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """读取内存"""
        if not self.script:
            logger.error("脚本未加载")
            return None
        
        try:
            return self.script.exports.readmemory(address, size)
        except Exception as e:
            logger.error(f"读取内存失败: {str(e)}")
            return None
    
    def write_memory(self, address: int, data: bytes) -> bool:
        """写入内存"""
        if not self.script:
            logger.error("脚本未加载")
            return False
        
        try:
            # 将字节数组转换为整数列表
            data_list = list(data)
            return self.script.exports.writememory(address, data_list)
        except Exception as e:
            logger.error(f"写入内存失败: {str(e)}")
            return False
    
    def write_value(self, address: int, value: Any, value_type: str) -> bool:
        """写入指定类型的值"""
        if not self.script:
            logger.error("脚本未加载")
            return False
        
        try:
            return self.script.exports.writevalue(address, value, value_type)
        except Exception as e:
            logger.error(f"写入值失败: {str(e)}")
            return False
    
    def search_memory(self, value_type: str, value: str, previous_results=None, start_addr=None, end_addr=None) -> list:
        """扫描内存"""
        try:
            if not self.script:
                raise Exception("未附加到进程")
            
            # 设置默认地址范围
            if start_addr is None:
                start_addr = 0x0
            if end_addr is None:
                end_addr = 0x7fffffffffff
            
            # 根据value_type确定byte_length
            type_sizes = {
                "UInt8": 1, "Int8": 1,
                "UInt16": 2, "Int16": 2,
                "UInt32": 4, "Int32": 4, "4字节": 4,
                "UInt64": 8, "Int64": 8, "8字节": 8,
                "Float": 4,
                "Double": 8,
                "String": None
            }
            
            byte_length = type_sizes.get(value_type, 4)
            
            # 处理输入值
            try:
                # 检查是否是16进制输入
                if isinstance(value, str) and value.lower().startswith('0x'):
                    processed_value = str(int(value, 16))
                elif value_type in ["Float", "Double"]:
                    processed_value = str(float(value))
                elif value_type == "String":
                    processed_value = str(value)
                else:
                    processed_value = str(int(value))
            except ValueError:
                logger.error(f"输入值格式错误: {value}")
                return []
            
            try:
                if previous_results is None:
                    # 首次扫描 - 使用 newscanbyprotect
                    count = self.script.exports.newscanbyprotect(
                        'rw-',  # 搜索可读写内存
                        processed_value,
                        byte_length
                    )
                else:
                    # 后续扫描
                    count = self.script.exports.nextnscanequal(processed_value)
                
                if count > 0:
                    results = self.script.exports.getscanresults()
                    return results
                return []
                
            except Exception as e:
                logger.error(f"扫描内存失败: {str(e)}")
                logger.debug(f"可用的导出函数: {dir(self.script.exports)}")
                return []
                
        except Exception as e:
            logger.error(f"内存扫描失败: {str(e)}")
            return []
    
    def watch_memory(self, address: int, size: int = 4) -> bool:
        """监控内存访问"""
        if not self.script:
            logger.error("脚本未加载")
            return False
        
        try:
            return self.script.exports.watchMemory(address, size)
        except Exception as e:
            logger.error(f"设置内存监控失败: {str(e)}")
            return False
    
    def __del__(self):
        """析构函数，确保资源被正确清理"""
        self.cleanup()