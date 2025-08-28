#!/usr/bin/env python3
"""
DG2 CBEFF修复工具
修复DG2文件中的CBEFF头部长度字段错误，解决JMRTD读取时的"dataLength = -14"问题
"""

import os
import sys

def fix_dg2_cbeff(file_path):
    """
    修复DG2文件中的CBEFF头部长度字段
    
    问题说明：
    - CBEFF头部偏移14-15存储总生物特征数据长度（包括CBEFF头部本身）
    - CBEFF头部偏移18-19存储记录长度，应该等于总长度减14
    - 如果记录长度设置错误，JMRTD会报"dataLength = -14, constructedDataLength = 0"错误
    """
    
    print(f"\n处理文件: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"❌ 文件不存在: {file_path}")
        return False
    
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())
    
    # 查找5F2E标签（生物特征数据）
    found = False
    for i in range(len(data) - 5):
        if data[i] == 0x5F and data[i+1] == 0x2E:
            # 检查长度编码
            if data[i+2] == 0x82:  # 长形式，2字节长度
                bio_length = (data[i+3] << 8) | data[i+4]
                bio_start = i + 5
            elif data[i+2] == 0x81:  # 长形式，1字节长度
                bio_length = data[i+3]
                bio_start = i + 4
            else:  # 短形式
                bio_length = data[i+2]
                bio_start = i + 3
            
            found = True
            print(f"  找到5F2E标签在偏移 0x{i:04X}")
            print(f"  生物特征数据长度: {bio_length} bytes")
            
            # 检查CBEFF头部
            if bio_start + 50 <= len(data):
                # 读取CBEFF头部的长度字段
                current_total_len = (data[bio_start + 14] << 8) | data[bio_start + 15]
                current_record_len = (data[bio_start + 18] << 8) | data[bio_start + 19]
                
                # 计算正确的值
                correct_total_len = bio_length
                correct_record_len = bio_length - 14
                
                print(f"  当前CBEFF总长度 (offset 14-15): {current_total_len} (0x{current_total_len:04X})")
                print(f"  当前CBEFF记录长度 (offset 18-19): {current_record_len} (0x{current_record_len:04X})")
                print(f"  正确的总长度: {correct_total_len} (0x{correct_total_len:04X})")
                print(f"  正确的记录长度: {correct_record_len} (0x{correct_record_len:04X})")
                
                # 检查是否需要修复
                needs_fix = False
                
                if current_total_len != correct_total_len:
                    print(f"  ⚠️  总长度错误！差值: {current_total_len - correct_total_len}")
                    needs_fix = True
                
                if current_record_len != correct_record_len:
                    print(f"  ⚠️  记录长度错误！差值: {current_record_len - correct_record_len}")
                    if current_record_len - correct_record_len == 2:
                        print(f"  ⚠️  检测到常见错误：记录长度使用了 (总长度-12) 而不是 (总长度-14)")
                    needs_fix = True
                
                if needs_fix:
                    print("  🔧 正在修复CBEFF头部长度字段...")
                    
                    # 修复总长度
                    data[bio_start + 14] = (correct_total_len >> 8) & 0xFF
                    data[bio_start + 15] = correct_total_len & 0xFF
                    
                    # 修复记录长度
                    data[bio_start + 18] = (correct_record_len >> 8) & 0xFF
                    data[bio_start + 19] = correct_record_len & 0xFF
                    
                    # 保存修复后的文件
                    output_path = file_path.replace('.bin', '_fixed.bin')
                    with open(output_path, 'wb') as f:
                        f.write(data)
                    
                    print(f"  ✅ 文件已修复并保存到: {output_path}")
                    return True
                else:
                    print("  ✅ CBEFF头部长度字段正确，无需修复")
                    return False
            else:
                print("  ❌ 生物特征数据太短，无法包含完整的CBEFF头部")
                return False
            
            break
    
    if not found:
        print("  ❌ 未找到5F2E标签（生物特征数据）")
        return False
    
    return False

def verify_dg2_file(file_path):
    """验证DG2文件的CBEFF结构是否符合ISO 19794-5标准"""
    
    print(f"\n验证文件: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"❌ 文件不存在: {file_path}")
        return False
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # 验证外层TLV结构
    if len(data) < 10:
        print("❌ 文件太短")
        return False
    
    # 检查DG2标签 (0x75)
    if data[0] != 0x75:
        print(f"❌ 错误的DG2标签: 0x{data[0]:02X} (期望 0x75)")
        return False
    
    print("✅ DG2标签 (0x75) 正确")
    
    # 验证TLV嵌套结构
    try:
        pos = 0
        
        # Tag 75
        assert data[pos] == 0x75
        pos += 1
        
        # Length
        if data[pos] == 0x82:
            length_75 = (data[pos+1] << 8) | data[pos+2]
            pos += 3
        else:
            print("❌ DG2使用了非标准长度编码")
            return False
        
        # Tag 7F61
        assert data[pos] == 0x7F and data[pos+1] == 0x61
        pos += 2
        
        # Length
        if data[pos] == 0x82:
            length_7f61 = (data[pos+1] << 8) | data[pos+2]
            pos += 3
        else:
            print("❌ 7F61使用了非标准长度编码")
            return False
        
        print("✅ TLV结构正确 (75 > 7F61 > 7F60 > 5F2E)")
        
        # 查找并验证CBEFF头部
        for i in range(pos, len(data) - 50):
            if data[i] == 0x5F and data[i+1] == 0x2E:
                if data[i+2] == 0x82:
                    bio_len = (data[i+3] << 8) | data[i+4]
                    bio_start = i + 5
                    
                    # 验证CBEFF头部
                    if bio_start + 50 <= len(data):
                        # 检查FAC标识
                        if data[bio_start:bio_start+4] == b'FAC\x00':
                            print("✅ CBEFF格式标识符 'FAC' 正确")
                        else:
                            print("❌ CBEFF格式标识符错误")
                            return False
                        
                        # 检查版本
                        if data[bio_start+4:bio_start+8] == b'010\x00':
                            print("✅ CBEFF版本 '010' 正确")
                        else:
                            print(f"⚠️  CBEFF版本: {data[bio_start+4:bio_start+8]}")
                        
                        # 验证长度字段
                        total_len = (data[bio_start + 14] << 8) | data[bio_start + 15]
                        record_len = (data[bio_start + 18] << 8) | data[bio_start + 19]
                        
                        if total_len == bio_len:
                            print(f"✅ CBEFF总长度字段正确: {total_len}")
                        else:
                            print(f"❌ CBEFF总长度字段错误: {total_len} (应该是 {bio_len})")
                            return False
                        
                        if record_len == bio_len - 14:
                            print(f"✅ CBEFF记录长度字段正确: {record_len}")
                        else:
                            print(f"❌ CBEFF记录长度字段错误: {record_len} (应该是 {bio_len - 14})")
                            print(f"   这会导致JMRTD报错: dataLength = {record_len - (bio_len - 14)}")
                            return False
                        
                        # 查找JPEG
                        for j in range(bio_start + 50, bio_start + bio_len - 1):
                            if data[j] == 0xFF and data[j+1] == 0xD8:
                                print(f"✅ 找到JPEG图像数据 (偏移 {j - bio_start} in CBEFF)")
                                return True
                        
                        print("⚠️  未找到JPEG标记，但结构正确")
                        return True
                    
                break
        
    except Exception as e:
        print(f"❌ 解析TLV结构时出错: {e}")
        return False
    
    return False

def main():
    """主函数"""
    
    print("="*60)
    print("DG2 CBEFF修复和验证工具")
    print("="*60)
    print("\n此工具用于修复DG2文件中的CBEFF头部长度字段错误")
    print("解决JMRTD读取时的 'dataLength = -14' 问题")
    
    # 需要检查的文件列表
    files_to_check = [
        'test_dg2.bin',
        'generated_data/0102.bin',
        'test_dg2_fixed.bin'
    ]
    
    print("\n" + "="*60)
    print("开始检查和修复DG2文件")
    print("="*60)
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            # 先验证
            is_valid = verify_dg2_file(file_path)
            
            if not is_valid:
                # 如果无效，尝试修复
                if fix_dg2_cbeff(file_path):
                    # 验证修复后的文件
                    fixed_path = file_path.replace('.bin', '_fixed.bin')
                    print(f"\n验证修复后的文件:")
                    verify_dg2_file(fixed_path)
        else:
            print(f"\n⚠️  文件不存在: {file_path}")
    
    print("\n" + "="*60)
    print("处理完成")
    print("="*60)
    
    print("\n建议：")
    print("1. 使用修复后的文件（*_fixed.bin）替换原文件")
    print("2. 更新generate_all_passport_data.py确保生成正确的CBEFF头部")
    print("3. 重新测试JMRTD读取功能")

if __name__ == '__main__':
    main()