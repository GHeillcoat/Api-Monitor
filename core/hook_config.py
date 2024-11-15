import json
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class HookRule:
    type: str  # "dll" 或 "custom"
    module: Optional[str]  # DLL名称（针对dll类型）
    function: Optional[str]  # 函数名（针对dll类型）
    base_addr: Optional[str]  # 基地址（针对custom类型）
    offset: Optional[str]  # 偏移（针对custom类型）
    args_count: int
    param_types: List[str]  # 每个参数的类型
    
class HookConfig:
    def __init__(self):
        self.rules: List[HookRule] = []
    
    def add_rule(self, rule: HookRule):
        self.rules.append(rule)
    
    def save_to_file(self, filename: str):
        data = [{
            "type": rule.type,
            "module": rule.module,
            "function": rule.function,
            "base_addr": rule.base_addr,
            "offset": rule.offset,
            "args_count": rule.args_count,
            "param_types": rule.param_types
        } for rule in self.rules]
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_from_file(self, filename: str):
        with open(filename, 'r') as f:
            data = json.load(f)
        
        self.rules = []
        for item in data:
            rule = HookRule(
                type=item["type"],
                module=item["module"],
                function=item["function"],
                base_addr=item["base_addr"],
                offset=item["offset"],
                args_count=item["args_count"],
                param_types=item["param_types"]
            )
            self.rules.append(rule) 