#!/usr/bin/env python3
"""
DG2文件结构分析和修复脚本
用于解决JMRTD读取DG2时的"dataLength = -14"错误
"""

import sys
import os

def analyze_tlv(data, offset=0, indent=0):
    """递归分析TLV结构"""
    results = []
    pos = offset
    
    while pos < len(data):
        # 读取标签
        tag = data[pos]
        tag_str = f"{tag:02X}"
        tag_len = 1
        
        # 检查是否是多字节标签
        if (tag & 0x1F) == 0x1F:
            pos += 1
            tag = (tag << 8) | data[pos]
            tag_str = f"{(tag >> 8):02X} {(tag & 0xFF):02X}"
            tag_len = 2
        
        pos += 1
        
        # 读取长度
        length_byte = data[pos]
        pos += 1
        
        if length_byte & 0x80:
            # 长形式
            num_length_bytes = length_byte & 0x7F
            length = 0
            for i in range(num_length_bytes):
                length = (length << 8) | data[pos]
                pos += 1
            length_form = f"82 {(length >> 8):02X} {(length & 0xFF):02X}" if num_length_bytes == 2 else f"{length_byte:02X} ..."
        else:
            # 短形式
            length = length_byte
            length_form = f"{length_byte:02X}"
        
        # 记录TLV信息
        indent_str = "  " * indent
        results.append(f"{indent_str}Tag {tag_str} (offset {offset + (pos - offset - tag_len - (1 if length_byte < 0x80 else 3)):04X}), Length: {length_form} ({length} bytes)")
        
        # 特殊处理某些标签
        if tag in [0x75, 0x7F61, 0x7F60]:
            # 递归解析嵌套结构
            sub_results = analyze_tlv(data[pos:pos+length], 0, indent + 1)
            results.extend(sub_results)
        elif tag == 0x5F2E:
            # 分析生物特征数据
            bio_data = data[pos:pos+length]
            if len(bio_data) >= 50:
                # 分析CBEFF头部
                results.append(f"{indent_str}  CBEFF Header Analysis:")
                results.append(f"{indent_str}    Format ID: {bio_data[0:4].hex()} ('{bio_data[0:4].decode('ascii', errors='ignore')}')")
                results.append(f"{indent_str}    Version: {bio_data[4:8].hex()} ('{bio_data[4:8].decode('ascii', errors='ignore')}')")
                
                # 关键长度字段
                total_len_offset_14 = (bio_data[14] << 8) | bio_data[15]
                record_len_offset_18 = (bio_data[18] << 8) | bio_data[19]
                
                results.append(f"{indent_str}    Total Length (offset 14-15): {total_len_offset_14:04X} ({total_len_offset_14} bytes)")
                results.append(f"{indent_str}    Record Length (offset 18-19): {record_len_offset_18:04X} ({record_len_offset_18} bytes)")
                results.append(f"{indent_str}    Actual 5F2E content length: {length} bytes")
                
                # 检查长度一致性
                if total_len_offset_14 != length:
                    results.append(f"{indent_str}    ⚠️  ERROR: Total length mismatch! Expected {length}, got {total_len_offset_14}")
                    results.append(f"{indent_str}    ⚠️  Difference: {length - total_len_offset_14} bytes")
                
                expected_record_len = length - 14
                if record_len_offset_18 != expected_record_len:
                    results.append(f"{indent_str}    ⚠️  ERROR: Record length mismatch! Expected {expected_record_len}, got {record_len_offset_18}")
                    results.append(f"{indent_str}    ⚠️  Difference: {expected_record_len - record_len_offset_18} bytes")
                    
                    # 这就是导致"dataLength = -14"错误的原因
                    if record_len_offset_18 - expected_record_len == 14:
                        results.append(f"{indent_str}    ⚠️  CRITICAL: This is causing 'dataLength = -14' error in JMRTD!")
                
                # 查找JPEG数据
                jpeg_start = -1
                for i in range(len(bio_data) - 1):
                    if bio_data[i] == 0xFF and bio_data[i+1] == 0xD8:
                        jpeg_start = i
                        break
                
                if jpeg_start >= 0:
                    results.append(f"{indent_str}    JPEG starts at offset {jpeg_start} in biometric data")
                    jpeg_size = length - jpeg_start
                    results.append(f"{indent_str}    JPEG size: {jpeg_size} bytes")
        
        pos += length
        
        # 防止无限循环
        if pos > len(data):
            results.append(f"{indent_str}⚠️  WARNING: TLV structure extends beyond data boundary!")
            break
    
    return results

def fix_dg2_file(input_file, output_file):
    """修复DG2文件中的CBEFF长度字段"""
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())
    
    print(f"\n修复文件: {input_file}")
    print(f"文件大小: {len(data)} bytes")
    
    # 查找5F2E标签
    for i in range(len(data) - 3):
        if data[i] == 0x5F and data[i+1] == 0x2E and data[i+2] == 0x82:
            # 找到5F2E标签，长形式
            length = (data[i+3] << 8) | data[i+4]
            bio_start = i + 5
            
            print(f"\n找到5F2E标签在偏移 {i:04X}")
            print(f"5F2E内容长度: {length} bytes")
            
            if bio_start + 50 <= len(data):
                # 读取当前的长度值
                current_total_len = (data[bio_start + 14] << 8) | data[bio_start + 15]
                current_record_len = (data[bio_start + 18] << 8) | data[bio_start + 19]
                
                print(f"当前总长度 (offset 14-15): {current_total_len}")
                print(f"当前记录长度 (offset 18-19): {current_record_len}")
                
                # 计算正确的长度
                correct_total_len = length
                correct_record_len = length - 14
                
                print(f"正确的总长度应该是: {correct_total_len}")
                print(f"正确的记录长度应该是: {correct_record_len}")
                
                if current_total_len != correct_total_len or current_record_len != correct_record_len:
                    print("\n⚠️  检测到长度字段错误，正在修复...")
                    
                    # 修复长度字段
                    data[bio_start + 14] = (correct_total_len >> 8) & 0xFF
                    data[bio_start + 15] = correct_total_len & 0xFF
                    data[bio_start + 18] = (correct_record_len >> 8) & 0xFF
                    data[bio_start + 19] = correct_record_len & 0xFF
                    
                    print("✅ 长度字段已修复!")
                    
                    # 保存修复后的文件
                    with open(output_file, 'wb') as f:
                        f.write(data)
                    print(f"✅ 修复后的文件已保存到: {output_file}")
                    return True
                else:
                    print("✅ 长度字段已经是正确的，无需修复")
                    return False
            break
    
    print("⚠️  未找到5F2E标签或文件结构异常")
    return False

def main():
    print("="*60)
    print("DG2文件结构分析和修复工具")
    print("="*60)
    
    # 分析test_dg2.bin
    if os.path.exists('test_dg2.bin'):
        print("\n分析 test_dg2.bin:")
        print("-"*40)
        with open('test_dg2.bin', 'rb') as f:
            data = f.read()
        results = analyze_tlv(data)
        for line in results:
            print(line)
    
    # 分析generated_data/0102.bin
    if os.path.exists('generated_data/0102.bin'):
        print("\n\n分析 generated_data/0102.bin:")
        print("-"*40)
        with open('generated_data/0102.bin', 'rb') as f:
            data = f.read()
        results = analyze_tlv(data)
        for line in results:
            print(line)
    
    # 修复文件
    print("\n\n" + "="*60)
    print("开始修复DG2文件")
    print("="*60)
    
    files_to_fix = ['test_dg2.bin', 'generated_data/0102.bin']
    
    for file_path in files_to_fix:
        if os.path.exists(file_path):
            output_path = file_path.replace('.bin', '_fixed.bin')
            if fix_dg2_file(file_path, output_path):
                print(f"\n✅ 成功修复: {file_path} -> {output_path}")
            else:
                print(f"\nℹ️  {file_path} 无需修复")
        else:
            print(f"\n⚠️  文件不存在: {file_path}")

if __name__ == '__main__':
    main()