function arraybuffer2hexstr(buffer) 
{
    var hexArr = Array.prototype.map.call(
      new Uint8Array(buffer),
      function (bit) {
        return ('00' + bit.toString(16)).slice(-2)
      }
    )
    return hexArr.join(' ');
}
 
function generate_pattern(input, byte_length)
{
    var pattern = null;
    var addr = 0;
    var array_buffer = null;

    // 首先将输入转换为数字（如果可能的话）
    if (typeof input === 'string') {
        if (input.indexOf('.') !== -1) {
            input = parseFloat(input);
        } else {
            input = parseInt(input);
        }
    }

    switch(byte_length)
    {
        case 1: //byte
            if(input >= 0) //无符号
            {
                addr = Memory.alloc(1)
                Memory.writeU8(addr, input)
                array_buffer = Memory.readByteArray(addr, 1)
                pattern = arraybuffer2hexstr(array_buffer)
            }else{ //有符号
                addr = Memory.alloc(1)
                Memory.writeS8(addr, input)
                array_buffer = Memory.readByteArray(addr, 1)
                pattern = arraybuffer2hexstr(array_buffer)
            }
        break;
        case 2: //short
            if(input >= 0)
            {
                addr = Memory.alloc(2)
                Memory.writeU16(addr, input)
                array_buffer = Memory.readByteArray(addr, 2)
                pattern = arraybuffer2hexstr(array_buffer)
            }else{
                addr = Memory.alloc(2)
                Memory.writeS16(addr, input)
                array_buffer = Memory.readByteArray(addr, 2)
                pattern = arraybuffer2hexstr(array_buffer)
            }
        break;
        case 4:
            if(Number.isInteger(input)) //int long
            {
                if(input >= 0)
                {
                    addr = Memory.alloc(4)
                    Memory.writeU32(addr, input)
                    array_buffer = Memory.readByteArray(addr, 4)
                    pattern = arraybuffer2hexstr(array_buffer)
                }else{
                    addr = Memory.alloc(4)
                    Memory.writeS32(addr, input)
                    array_buffer = Memory.readByteArray(addr, 4)
                    pattern = arraybuffer2hexstr(array_buffer)
                }
            }else{ //float
                addr = Memory.alloc(4)
                Memory.writeFloat(addr, input)
                array_buffer = Memory.readByteArray(addr, 4)
                pattern = arraybuffer2hexstr(array_buffer)
            }
        break
        case 8:
            if(Number.isInteger(input)) //longlong
            {
                if(input >= 0)
                {
                    addr = Memory.alloc(8)
                    Memory.writeU64(addr, input)
                    array_buffer = Memory.readByteArray(addr, 8)
                    pattern = arraybuffer2hexstr(array_buffer)
                }else{
                    addr = Memory.alloc(8)
                    Memory.writeS64(addr, input)
                    array_buffer = Memory.readByteArray(addr, 8)
                    pattern = arraybuffer2hexstr(array_buffer)
                }
            }else{ //double
                addr = Memory.alloc(8)
                Memory.writeDouble(addr, input)
                array_buffer = Memory.readByteArray(addr, 8)
                pattern = arraybuffer2hexstr(array_buffer)
            }
        break;
        case undefined: //string
            var encoder = new TextEncoder('utf-8')
            array_buffer = encoder.encode(input)
            pattern = arraybuffer2hexstr(array_buffer)
        break
        default:
            pattern = 'error'
    }
    return pattern
}
 
function readValue(addr, input, byte_length)
{
    var result = 0;
    var addr_ptr = new NativePointer(addr);
 
    switch(byte_length)
    {
        case 1: //byte
            if(input >= 0) //无符号
            {
                result = Memory.readU8(addr_ptr)
            }else{ //有符号
                result = Memory.readS8(addr_ptr)
            }
        break;
        case 2: //short
            if(input >= 0)
            {
                result = Memory.readU16(addr_ptr)
            }else{
                result = Memory.readS16(addr_ptr)
            }
        break;
        case 4:
            if(parseInt(input) == input) //int long
            {
                if(input >= 0)
                {
                    result = Memory.readU32(addr_ptr)
                }else{
                    result = Memory.readS32(addr_ptr)
                }
            }else{ //float
                result = Memory.readFloat(addr_ptr)
            }
        break
        case 8:
            if(parseInt(input) == input) //longlong
            {
                if(input >= 0)
                {
                    result = Memory.readU64(addr_ptr)
                }else{
                    result = Memory.readS64(addr_ptr)
                }
            }else{ //double
                result = Memory.readDouble(addr_ptr)
            }
        break;
        case undefined: //string
            result = Memory.readUtf8String(addr_ptr)
        break
        default:
            result = 'error'
    }
    return result;
}
function init_scan_range()
{
    // 根据操作系统返回不同的结果
    if (Process.platform === 'windows') {
        // Windows 平台直接返回空数组，让 new_scan_by_protect 处理内存范围
        return [];
    } else {
        // Linux 平台的原有代码
        var buffer_length = 1024;
        var result = [];
     
        addr = Module.findExportByName('libc.so', 'popen');
        var popen = new NativeFunction(addr, 'pointer', ['pointer', 'pointer']);
     
        addr = Module.findExportByName('libc.so', 'fgets');
        var fgets = new NativeFunction(addr, "pointer", ["pointer", "int", "pointer"]);
     
        addr = Module.findExportByName('libc.so', 'pclose');
        var pclose = new NativeFunction(addr, "int", ["pointer"]);
     
        var pid = Process.id;
        var command = 'cat /proc/' + pid + '/maps |grep LinearAlloc';
        var pfile = popen(Memory.allocUtf8String(command), Memory.allocUtf8String('r'));
        if(pfile == null)
        {
            console.log("打开文件失败...");
            return [];
        }
     
        var buffer = Memory.alloc(buffer_length);
     
        while (fgets(buffer, buffer_length, pfile) > 0) {
            var str = Memory.readUtf8String(buffer);
            result.push([ptr(parseInt(str.substr(0, 8), 16)), ptr(parseInt(str.substr(9, 8), 16))]);
        }
        pclose(pfile);
        return result;
    }
}
var g_data = {};
var init_value = 0;
var init_byte_length = 0;
 
function new_scan_by_addr(addr_start, addr_end, input, byte_length)
{
    var m_count = 0
    g_data = {}
    init_value = input
    init_byte_length = byte_length
 
    var _addr_start = new NativePointer(addr_start)
    var _addr_end = new NativePointer(addr_end)
    var pattern = generate_pattern(init_value, init_byte_length)
    if(pattern == 'error')
    {
        console.log('错误: 字节长度只能是 1, 2, 4, 8 或未定义')
        return 0;
    }
    var searchResult_list = Memory.scanSync(_addr_start, _addr_end - _addr_start, pattern)
    for(index in searchResult_list)
    {
        g_data[searchResult_list[index].address] = input
    }
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
function new_scan_by_protect(protection, input, byte_length)
{
    var m_count = 0;
    var searchResult_list = [];
 
    g_data = {};
    init_value = input;
    init_byte_length = byte_length;
 
    var pattern = generate_pattern(init_value, init_byte_length);
    if(pattern == 'error')
    {
        console.log('错误: 字节长度只能是 1, 2, 4, 8 或未定义');
        return 0;
    }
    
    var range_list = Process.enumerateRangesSync(protection);
    for(let i = 0; i < range_list.length; i++)
    {
        try{
            let results = Memory.scanSync(range_list[i].base, range_list[i].size, pattern);
            searchResult_list = searchResult_list.concat(results);
        }catch(e){
            continue;
        }
    }
    
    for(let i = 0; i < searchResult_list.length; i++)
    {
        g_data[searchResult_list[i].address] = input;
    }
    
    m_count = Object.keys(g_data).length;
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
function new_scan_by_addr_unknownValue(addr_start, addr_end, reference, byte_length)
{
    var m_count = 0
    g_data = {}
    init_value = reference
    init_byte_length = byte_length
 
    var _addr_start = new NativePointer(addr_start)
    var _addr_end = new NativePointer(addr_end)
    while(_addr_start.toInt32() < _addr_end.toInt32())
    {
        g_data[_addr_start] = readValue(_addr_start, init_value, init_byte_length)
        _addr_start = _addr_start.add(byte_length)
    }
     
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
function new_scan_by_addr_larger(addr_start, addr_end, value, byte_length)
{
    var m_count = 0
    g_data = {}
    init_value = value
    init_byte_length = byte_length
 
    var _addr_start = new NativePointer(addr_start)
    var _addr_end = new NativePointer(addr_end)
    while(_addr_start.toInt32() < _addr_end.toInt32())
    {
         
        var new_value= readValue(_addr_start, init_value, init_byte_length)
        if(new_value > value)
        {
            g_data[_addr_start] = new_value
        }
        _addr_start = _addr_start.add(byte_length)
    }
     
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
 
function new_scan_by_addr_littler(addr_start, addr_end, value, byte_length)
{
    var m_count = 0
    g_data = {}
    init_value = value
    init_byte_length = byte_length
 
    var _addr_start = new NativePointer(addr_start)
    var _addr_end = new NativePointer(addr_end)
    while(_addr_start.toInt32() < _addr_end.toInt32())
    {
         
        var new_value= readValue(_addr_start, init_value, init_byte_length)
        if(new_value < value)
        {
            g_data[_addr_start] = new_value
        }
        _addr_start = _addr_start.add(byte_length)
    }
     
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
 
function new_scan_by_addr_between(addr_start, addr_end, value1, value2, byte_length)
{
    var m_count = 0
    g_data = {}
    init_value = value1
    init_byte_length = byte_length
 
    var _addr_start = new NativePointer(addr_start)
    var _addr_end = new NativePointer(addr_end)
    while(_addr_start.toInt32() < _addr_end.toInt32())
    {
         
        var new_value= readValue(_addr_start, init_value, init_byte_length)
        if(new_value >= value1 && new_value <= value2)
        {
            g_data[_addr_start] = new_value
        }
        _addr_start = _addr_start.add(byte_length)
    }
     
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
function next_scan_equal(value)
{
    var m_count = 0;
 
    for(key in g_data)
    {
 
        if(readValue(key, init_value, init_byte_length) != value)
        {
            delete g_data[key]
        }else{
            g_data[key] = value
        }
    }
 
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
 
function next_scan_unchange()
{
    var m_count = 0;
 
    for(key in g_data)
    {
 
        if(readValue(key, init_value, init_byte_length) != g_data[key])
        {
            delete g_data[key]
        }
    }
 
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
 
function next_scan_change()
{
    var m_count = 0;
 
    for(key in g_data)
    {
        var new_value = readValue(key, init_value, init_byte_length)
        if(new_value == g_data[key])
        {
            delete g_data[key]
        }else{
            g_data[key] = new_value
        }
    }
 
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
 
function next_scan_larger(value)
{
    var m_count = 0;
 
    for(key in g_data)
    {
        var new_value = readValue(key, init_value, init_byte_length)
        if(new_value <= value)
        {
            delete g_data[key]
        }else{
            g_data[key] = new_value
        }
    }
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
 
function next_scan_littler(value)
{
    var m_count = 0;
 
    for(key in g_data)
    {
        var new_value = readValue(key, init_value, init_byte_length)
        if(new_value >= value)
        {
            delete g_data[key]
        }else{
            g_data[key] = new_value
        }
    }
 
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
 
function next_scan_between(value1, value2)
{
    var m_count = 0;
 
    for(key in g_data)
    {
        var new_value = readValue(key, init_value, init_byte_length)
        if(new_value >= value1 && new_value <= value2)
        {
            g_data[key] = new_value
        }else{
            delete g_data[key]
        }
    }
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
 
function next_scan_increase()
{
    var m_count = 0;
 
    for(key in g_data)
    {
        var new_value = readValue(key, init_value, init_byte_length)
        if(new_value <= g_data[key])
        {
            delete g_data[key]
        }else{
            g_data[key] = new_value
        }
    }
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}
 
function next_scan_decrease()
{
    var m_count = 0;
 
    for(key in g_data)
    {
        var new_value = readValue(key, init_value, init_byte_length)
        if(new_value >= g_data[key])
        {
            delete g_data[key]
        }else{
            g_data[key] = new_value
        }
    }
    m_count  = Object.keys(g_data).length
    if(m_count < 100)
    {
        for(var key in g_data)
        {
            console.log("地址: " + key + " 值: " + g_data[key]);
        }
    }
    return m_count;
}

function get_scan_results() {
    var results = [];
    for(var key in g_data) {
        results.push([key, g_data[key]]);
    }
    return results;
}

// 添加内存读写函数
function readMemory(address, size) {
    try {
        var addr_ptr = new NativePointer(address);
        return Memory.readByteArray(addr_ptr, size);
    } catch(e) {
        return null;
    }
}

// 修改内存写入函数
function writeMemory(address, data) {
    try {
        var addr_ptr = new NativePointer(address);
        // 将传入的数组转换回 ArrayBuffer
        var buffer = new Uint8Array(data).buffer;
        Memory.protect(addr_ptr, buffer.byteLength, 'rwx');  // 确保内存可写
        Memory.writeByteArray(addr_ptr, buffer);
        return true;
    } catch(e) {
        console.log("写入内存失败:", e);
        return false;
    }
}

// 修改写入函数，添加更好的错误处理和权限管理
function writeValue(address, value, type) {
    try {
        var addr_ptr = new NativePointer(address);
        
        // 获取内存页信息
        var pageSize = Process.pageSize;
        var pageAddr = addr_ptr.and(~(pageSize - 1));
        var size = 8;  // 使用最大可能的大小
        
        // 获取当前内存保护
        var oldProtection = null;
        try {
            var protection = Process.findRangeByAddress(addr_ptr).protection;
            oldProtection = protection;
            
            // 如果内存不可写，尝试修改权限
            if (!protection.includes('w')) {
                Memory.protect(pageAddr, pageSize, 'rwx');
            }
        } catch(e) {
            console.log("获取或修改内存保护失败:", e);
            return false;
        }
        
        // 写入值
        try {
            switch(type) {
                case 'UInt8':
                    Memory.writeU8(addr_ptr, parseInt(value));
                    break;
                case 'Int8':
                    Memory.writeS8(addr_ptr, parseInt(value));
                    break;
                case 'UInt16':
                    Memory.writeU16(addr_ptr, parseInt(value));
                    break;
                case 'Int16':
                    Memory.writeS16(addr_ptr, parseInt(value));
                    break;
                case 'UInt32':
                    Memory.writeU32(addr_ptr, parseInt(value));
                    break;
                case 'Int32':
                    Memory.writeS32(addr_ptr, parseInt(value));
                    break;
                case 'UInt64':
                    Memory.writeU64(addr_ptr, parseInt(value));
                    break;
                case 'Int64':
                    Memory.writeS64(addr_ptr, parseInt(value));
                    break;
                case 'Float':
                    Memory.writeFloat(addr_ptr, parseFloat(value));
                    break;
                case 'Double':
                    Memory.writeDouble(addr_ptr, parseFloat(value));
                    break;
                case 'String':
                    Memory.writeUtf8String(addr_ptr, value.toString());
                    break;
                default:
                    return false;
            }
            
            // 恢复原始保护
            if (oldProtection && oldProtection !== 'rwx') {
                Memory.protect(pageAddr, pageSize, oldProtection);
            }
            
            return true;
        } catch(e) {
            console.log("写入值失败:", e);
            // 尝试恢复原始保护
            if (oldProtection && oldProtection !== 'rwx') {
                try {
                    Memory.protect(pageAddr, pageSize, oldProtection);
                } catch(e) {}
            }
            return false;
        }
    } catch(e) {
        console.log("写入操作失败:", e);
        return false;
    }
}

// 修改导出部分，添加新的写入函数
rpc.exports = {
    initscanrange: init_scan_range,
    newscanbyprotect: new_scan_by_protect,
    newscanbyaddr: new_scan_by_addr,
    nextnscanequal: next_scan_equal,
    nextscanunchange: next_scan_unchange,
    nextscanchange: next_scan_change,
    nextscanlarger: next_scan_larger,
    nextscanlittler: next_scan_littler,
    nextscanbetween: next_scan_between,
    nextscanincrease: next_scan_increase,
    nextscandecrease: next_scan_decrease,
    getscanresults: get_scan_results,
    // 添加内存读写函数的导出
    readmemory: readMemory,
    writememory: writeMemory,
    writevalue: writeValue  // 添加新的写入函数
};