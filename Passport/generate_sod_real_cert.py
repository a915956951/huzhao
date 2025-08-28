#!/usr/bin/env python3
"""
使用真实的阿联酋CSCA证书生成SOD文件
处理ECDSA explicit parameters的特殊情况
"""
import os
import hashlib
from datetime import datetime

class RealCertSODGenerator:
    def __init__(self):
        self.real_cert_path = '115.cer'  # 使用更新的证书
        self.dg_files_dir = 'generated_data'
        self.output_file = 'generated_data/011D.bin'
        
        # DG文件映射
        self.dg_file_mapping = {
            1:  ('0101.bin', 0x61),
            2:  ('0102.bin', 0x75), 
            11: ('010B.bin', 0x6B),
            12: ('010C.bin', 0x6C),
            15: ('010F.bin', 0x6F),
        }
    
    def encode_tlv(self, tag, value):
        """TLV编码"""
        if isinstance(tag, int):
            if tag <= 0xFF:
                tag_bytes = bytes([tag])
            elif tag <= 0xFFFF:
                tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF])
            else:
                tag_bytes = bytes([(tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF])
        else:
            tag_bytes = tag
        
        length = len(value)
        if length < 128:
            length_bytes = bytes([length])
        elif length < 256:
            length_bytes = bytes([0x81, length])
        elif length < 65536:
            length_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            length_bytes = bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
        
        return tag_bytes + length_bytes + value
    
    def calculate_dg_hashes(self):
        """计算所有DG文件的哈希值"""
        print("正在计算DG文件哈希值...")
        
        dg_hashes = {}
        for dg_num, (filename, tlv_tag) in self.dg_file_mapping.items():
            file_path = os.path.join(self.dg_files_dir, filename)
            
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    dg_data = f.read()
                
                dg_hash = hashlib.sha256(dg_data).digest()
                dg_hashes[dg_num] = dg_hash
                
                print(f"  DG{dg_num:02d} ({filename}): {len(dg_data):4d}字节, 哈希: {dg_hash.hex()[:16]}...")
            else:
                print(f"  警告: DG{dg_num:02d} 文件未找到: {file_path}")
        
        return dg_hashes
    
    def build_lds_security_object(self, dg_hashes):
        """构建LDS Security Object"""
        print("正在构建LDS Security Object...")
        
        # 版本号 (INTEGER 0)
        version = self.encode_tlv(0x02, bytes([0x00]))
        
        # 哈希算法标识符 (SHA-256)
        sha256_oid = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        hash_alg = self.encode_tlv(0x30, self.encode_tlv(0x06, sha256_oid))
        
        # DataGroupHashValues
        dg_hash_seq = b''
        for dg_num in sorted(dg_hashes.keys()):
            dg_hash = dg_hashes[dg_num]
            
            # 每个DG的哈希条目
            dg_number = self.encode_tlv(0x02, bytes([dg_num]))
            dg_hash_value = self.encode_tlv(0x04, dg_hash)
            
            dg_hash_entry = self.encode_tlv(0x30, dg_number + dg_hash_value)
            dg_hash_seq += dg_hash_entry
        
        dg_hash_values = self.encode_tlv(0x30, dg_hash_seq)
        
        # 完整的LDS Security Object
        lds_so = self.encode_tlv(0x30, version + hash_alg + dg_hash_values)
        
        print(f"  -> LDS Security Object构建完成 ({len(lds_so)}字节)")
        return lds_so
    
    def load_real_certificate(self):
        """加载真实的CSCA证书（原始字节格式）"""
        print(f"正在加载真实证书: {self.real_cert_path}")
        
        with open(self.real_cert_path, 'rb') as f:
            cert_data = f.read()
        
        print(f"  -> 证书加载成功 ({len(cert_data)}字节)")
        print(f"     序列号: 115")
        print(f"     主题: C=AE,O=MOI,OU=EPASS,CN=UAE CSCA 01")
        print(f"     算法: ecdsa-with-SHA256")
        
        return cert_data
    
    def create_mock_signature(self, data_to_sign):
        """
        创建模拟ECDSA签名
        注意：这是用于测试的模拟签名，不是真实的密码学签名
        """
        print("正在创建模拟ECDSA签名...")
        
        # 创建一个标准的ECDSA P-256签名格式 (DER编码)
        # SEQUENCE { r INTEGER, s INTEGER }
        # P-256的r和s各32字节
        
        # 使用数据的SHA-256哈希作为"签名"的基础
        data_hash = hashlib.sha256(data_to_sign).digest()
        
        # 生成模拟的r和s值（基于数据哈希）
        r_value = data_hash
        s_value = hashlib.sha256(data_hash + b'signature').digest()
        
        # DER编码INTEGER (去掉前导零，如果最高位是1则加00前缀)
        def encode_der_integer(value):
            if value[0] & 0x80:  # 最高位是1，需要加00前缀
                return self.encode_tlv(0x02, b'\x00' + value)
            else:
                return self.encode_tlv(0x02, value)
        
        r_der = encode_der_integer(r_value)
        s_der = encode_der_integer(s_value)
        
        # SEQUENCE包装
        signature = self.encode_tlv(0x30, r_der + s_der)
        
        print(f"  -> 模拟签名生成完成 ({len(signature)}字节)")
        return signature
    
    def build_pkcs7_signed_data(self, lds_so, cert_data):
        """构建PKCS#7 SignedData结构"""
        print("正在构建PKCS#7 SignedData...")
        
        # 1. ContentInfo中的content type OID (LDS Security Object)
        lds_so_oid = bytes([0x67, 0x81, 0x08, 0x01, 0x01, 0x01])  # 2.23.136.1.1.1
        
        # 2. 封装的内容
        encap_content = self.encode_tlv(0x30,
            self.encode_tlv(0x06, lds_so_oid) +
            self.encode_tlv(0xA0, self.encode_tlv(0x04, lds_so))
        )
        
        # 3. 算法标识符
        sha256_oid = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        digest_algorithms = self.encode_tlv(0x31,
            self.encode_tlv(0x30, self.encode_tlv(0x06, sha256_oid))
        )
        
        # 4. 证书
        certificates = self.encode_tlv(0xA0, cert_data)
        
        # 5. SignerInfo
        # 版本
        version = self.encode_tlv(0x02, bytes([0x01]))
        
        # 发行者和序列号（从115.cer证书中提取）
        issuer_name = self.encode_tlv(0x30, 
            self.encode_tlv(0x31, self.encode_tlv(0x30, 
                self.encode_tlv(0x06, bytes([0x55, 0x04, 0x06])) +
                self.encode_tlv(0x13, b'AE')
            )) +
            self.encode_tlv(0x31, self.encode_tlv(0x30,
                self.encode_tlv(0x06, bytes([0x55, 0x04, 0x0A])) +
                self.encode_tlv(0x0C, b'MOI')
            )) +
            self.encode_tlv(0x31, self.encode_tlv(0x30,
                self.encode_tlv(0x06, bytes([0x55, 0x04, 0x0B])) +
                self.encode_tlv(0x0C, b'EPASS')
            )) +
            self.encode_tlv(0x31, self.encode_tlv(0x30,
                self.encode_tlv(0x06, bytes([0x55, 0x04, 0x03])) +
                self.encode_tlv(0x0C, b'UAE CSCA 01')
            ))
        )
        
        serial_number = self.encode_tlv(0x02, bytes([0x73]))  # 115 = 0x73
        
        issuer_and_serial = self.encode_tlv(0x30, issuer_name + serial_number)
        
        # 摘要算法
        digest_algorithm = self.encode_tlv(0x30, self.encode_tlv(0x06, sha256_oid))
        
        # 签名属性
        content_type_attr = self.encode_tlv(0x30,
            self.encode_tlv(0x06, bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03])) +
            self.encode_tlv(0x31, self.encode_tlv(0x06, lds_so_oid))
        )
        
        # 消息摘要
        lds_digest = hashlib.sha256(lds_so).digest()
        message_digest_attr = self.encode_tlv(0x30,
            self.encode_tlv(0x06, bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04])) +
            self.encode_tlv(0x31, self.encode_tlv(0x04, lds_digest))
        )
        
        signed_attrs = self.encode_tlv(0xA0, content_type_attr + message_digest_attr)
        
        # 签名算法（ECDSA-with-SHA256）
        ecdsa_sha256_oid = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])
        signature_algorithm = self.encode_tlv(0x30, self.encode_tlv(0x06, ecdsa_sha256_oid))
        
        # 生成模拟签名
        attrs_for_signing = self.encode_tlv(0x31, content_type_attr + message_digest_attr)
        signature = self.create_mock_signature(attrs_for_signing)
        signature_value = self.encode_tlv(0x04, signature)
        
        # 组装SignerInfo
        signer_info = self.encode_tlv(0x30,
            version + issuer_and_serial + digest_algorithm + 
            signed_attrs + signature_algorithm + signature_value
        )
        
        signer_infos = self.encode_tlv(0x31, signer_info)
        
        # SignedData版本
        signed_data_version = self.encode_tlv(0x02, bytes([0x03]))
        
        # 组装SignedData
        signed_data = self.encode_tlv(0x30,
            signed_data_version + digest_algorithms + encap_content + 
            certificates + signer_infos
        )
        
        # 外层ContentInfo
        pkcs7_signed_data_oid = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
        content_info = self.encode_tlv(0x30,
            self.encode_tlv(0x06, pkcs7_signed_data_oid) +
            self.encode_tlv(0xA0, signed_data)
        )
        
        print(f"  -> PKCS#7 SignedData构建完成 ({len(content_info)}字节)")
        return content_info
    
    def generate_sod(self):
        """生成完整的SOD文件"""
        print("=== 开始生成SOD文件（使用真实CSCA证书） ===")
        print(f"配置信息:")
        print(f"  证书文件: {self.real_cert_path}")
        print(f"  DG文件目录: {self.dg_files_dir}")
        print(f"  输出文件: {self.output_file}")
        print()
        
        try:
            # 1. 加载真实证书
            cert_data = self.load_real_certificate()
            
            # 2. 计算DG哈希值
            dg_hashes = self.calculate_dg_hashes()
            if not dg_hashes:
                raise Exception("没有找到任何DG文件")
            
            # 3. 构建LDS Security Object
            lds_so = self.build_lds_security_object(dg_hashes)
            
            # 4. 构建PKCS#7 SignedData
            pkcs7_data = self.build_pkcs7_signed_data(lds_so, cert_data)
            
            # 5. 添加TLV外层包装
            sod_with_tlv = self.encode_tlv(0x77, pkcs7_data)
            
            # 6. 保存SOD文件
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            with open(self.output_file, 'wb') as f:
                f.write(sod_with_tlv)
            
            print(f"✅ SOD文件生成成功!")
            print(f"   文件路径: {self.output_file}")
            print(f"   文件大小: {len(sod_with_tlv)}字节")
            print(f"   使用证书: 阿联酋CSCA 115 (真实证书)")
            print(f"   包含DG: {', '.join([f'DG{num:02d}' for num in sorted(dg_hashes.keys())])}")
            
            return self.output_file
            
        except Exception as e:
            print(f"❌ SOD生成失败: {e}")
            raise

def main():
    """主函数"""
    print("使用真实阿联酋CSCA证书生成SOD文件")
    print("="*50)
    
    generator = RealCertSODGenerator()
    
    # 检查必需文件
    if not os.path.exists(generator.real_cert_path):
        print(f"❌ 错误: 证书文件不存在: {generator.real_cert_path}")
        return
    
    if not os.path.exists(generator.dg_files_dir):
        print(f"❌ 错误: DG文件目录不存在: {generator.dg_files_dir}")
        return
    
    # 生成SOD
    try:
        sod_file = generator.generate_sod()
        print(f"\n🎉 成功！现在SOD文件使用真实的阿联酋CSCA证书")
        print(f"请重新上传到智能卡并用JMRTD验证DS状态")
        
    except Exception as e:
        print(f"\n❌ 生成失败: {e}")

if __name__ == "__main__":
    main()