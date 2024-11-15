import psutil
from typing import List, Dict
from dataclasses import dataclass
import os
import win32process
import win32con
import win32api
from core.logger import logger

@dataclass
class ProcessInfo:
    pid: int
    name: str
    path: str
    memory_usage: float
    cpu_usage: float
    is_accessible: bool

class ProcessManager:
    def __init__(self):
        self._processes: Dict[int, ProcessInfo] = {}
        self._filtered_processes: List[ProcessInfo] = []
        self._filter_text = ""
        
    def refresh_process_list(self) -> List[ProcessInfo]:
        """刷新进程列表"""
        self._processes.clear()
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info', 'cpu_percent']):
            try:
                proc_info = proc.info
                # 获取进程权限
                try:
                    handle = win32api.OpenProcess(
                        win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                        False, 
                        proc_info['pid']
                    )
                    is_accessible = True
                    win32api.CloseHandle(handle)
                except:
                    is_accessible = False
                
                self._processes[proc_info['pid']] = ProcessInfo(
                    pid=proc_info['pid'],
                    name=proc_info['name'],
                    path=proc_info['exe'] or '',
                    memory_usage=proc_info['memory_info'].rss / 1024 / 1024,  # MB
                    cpu_usage=proc_info['cpu_percent'],
                    is_accessible=is_accessible
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        self._apply_filter()
        return self._filtered_processes
    
    def set_filter(self, filter_text: str):
        """设置过滤条件"""
        self._filter_text = filter_text.lower()
        self._apply_filter()
        
    def _apply_filter(self):
        """应用过滤条件"""
        if not self._filter_text:
            self._filtered_processes = list(self._processes.values())
        else:
            self._filtered_processes = [
                proc for proc in self._processes.values()
                if (self._filter_text in proc.name.lower() or
                    self._filter_text in str(proc.pid) or
                    self._filter_text in proc.path.lower())
            ]
        
    def get_process_info(self, pid: int) -> ProcessInfo:
        """获取指定进程信息"""
        return self._processes.get(pid)