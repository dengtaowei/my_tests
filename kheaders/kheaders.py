#!/usr/bin/env python3
import re
from collections import defaultdict, OrderedDict

def parse_struct_dump(text):
    structs = OrderedDict()
    current_struct = None
    
    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue
            
        # 匹配结构体开始
        begin_match = re.match(r'# STRUCT_BEGIN struct (\w+) (\d+)', line)
        if begin_match:
            struct_name = begin_match.group(1)
            struct_size = int(begin_match.group(2))
            current_struct = {
                'name': struct_name,
                'size': struct_size,
                'fields': []
            }
            continue
            
        # 匹配结构体结束
        end_match = re.match(r'# STRUCT_END struct (\w+)', line)
        if end_match:
            if current_struct and current_struct['name'] == end_match.group(1):
                structs[current_struct['name']] = current_struct
                current_struct = None
            continue
            
        # 匹配字段行
        field_match = re.match(
            r'FIELD: (\w+) offset=(\d+) size=(\d+)(?: type=(\w+))?', 
            line
        )
        if field_match and current_struct:
            field_name = field_match.group(1)
            offset = int(field_match.group(2))
            size = int(field_match.group(3))
            type_hint = field_match.group(4)
            
            current_struct['fields'].append({
                'name': field_name,
                'offset': offset,
                'size': size,
                'type': type_hint
            })
    
    return structs

def determine_field_type(field, structs):
    """智能确定字段类型，考虑内核特定类型"""
    name = field['name']
    size = field['size']
    
    # 如果有显式类型提示
    if field['type']:
        return f"struct {field['type']}"
    
    # 特殊字段类型映射
    special_types = {
        # 网络相关
        'skc_daddr': '__be32',
        'skc_rcv_saddr': '__be32',
        'skc_dport': '__be16',
        'skc_num': 'u16',
        'skc_family': 'u16',
        'skc_state': 'u8',
        'protocol': '__be16',
        'tcp_flags': 'u8',
        'flags': 'unsigned int',
        'state': 'unsigned long',
        'ifindex': 'int',
        'trans_start': 'unsigned long',
        'qlen': 'unsigned int',
        'head': 'void *',
        'dev': 'struct net_device *',
        'sk': 'struct sock *',
        
        # 定时器相关
        'expires': 'unsigned long',
        'timeout': 'unsigned long',
        
        # 缓冲区相关
        'data': 'void *',
        'data_end': 'void *',
        'seq': 'u32',
    }
    
    # 检查特殊字段名
    if name in special_types:
        return special_types[name]
    
    # 根据大小推断基本类型
    size_map = {
        1: 'u8',
        2: 'u16',
        4: 'u32',
        8: 'u64'
    }
    
    if size in size_map:
        return size_map[size]
    
    # 默认使用字节数组
    return f"unsigned char __{name}_buf[{size}]"

def generate_c_code(structs):
    # 按照依赖关系排序结构体
    ordered_structs = []
    remaining_structs = list(structs.keys())
    
    # 简单的依赖排序
    while remaining_structs:
        for name in remaining_structs[:]:
            deps = set()
            for field in structs[name]['fields']:
                if field['type'] and field['type'] in remaining_structs:
                    deps.add(field['type'])
            
            if not deps:
                ordered_structs.append(name)
                remaining_structs.remove(name)
    
    # 生成C代码
    code = """#ifndef __GENERATED_STRUCTS_H__
#define __GENERATED_STRUCTS_H__

/*
 * 自动生成的结构体定义
 * 注释格式: [起始偏移-结束偏移] 大小
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/timer.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

"""
    
    for name in ordered_structs:
        struct = structs[name]
        code += f"struct {name} {{\n"
        
        prev_offset = 0
        padding_id = 1
        
        for field in sorted(struct['fields'], key=lambda x: x['offset']):
            # 处理填充
            if field['offset'] > prev_offset:
                padding_size = field['offset'] - prev_offset
                end_offset = field['offset'] - 1
                code += f"    unsigned char __padding{padding_id}[{padding_size}]; /* [{prev_offset}-{end_offset}] {padding_size} bytes */\n"
                padding_id += 1
                prev_offset = field['offset']
            
            # 确定类型
            c_type = determine_field_type(field, structs)
            
            # 计算字段结束偏移
            field_end = field['offset'] + field['size'] - 1
            
            # 打印字段并在行末添加详细注释
            if '[' in c_type and ']' in c_type:
                code += f"    {c_type.split('[')[0]} {field['name']}[{c_type.split('[')[1].split(']')[0]}]; /* [{field['offset']}-{field_end}] {field['size']} bytes */\n"
            else:
                code += f"    {c_type} {field['name']}; /* [{field['offset']}-{field_end}] {field['size']} bytes */\n"
            prev_offset = field['offset'] + field['size']
        
        # 尾部填充
        if prev_offset < struct['size']:
            padding_size = struct['size'] - prev_offset
            end_offset = struct['size'] - 1
            code += f"    unsigned char __padding{padding_id}[{padding_size}]; /* [{prev_offset}-{end_offset}] {padding_size} bytes */\n"
        
        code += f"}} __attribute__((packed)); /* total size: {struct['size']} bytes */\n\n"
    
    code += "#endif /* __GENERATED_STRUCTS_H__ */\n"
    return code


if __name__ == "__main__":
    with open('text.txt', 'r') as f:
        text = f.read()

    structs = parse_struct_dump(text)
    c_code = generate_c_code(structs)
    print(c_code)  # 直接打印到控制台