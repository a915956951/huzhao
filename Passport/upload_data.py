#!/usr/bin/env python3
"""
护照数据上传脚本
基于Java代码分析得出的正确流程

正确的上传步骤：
1. 选择小程序
2. 设置MRZ数据（初始化BAC密钥，使用DG1中的数据）
3. 创建并上传所有文件（COM, DG1, DG2, DG11, DG12, DG15, SOD）
4. （可选）锁定小程序
5. 测试BAC认证
"""

import os
import struct
import time
import hashlib
from binascii import hexlify
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.CardConnection import CardConnection
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardConnectionException, NoCardException
from Crypto.Cipher import DES3, DES
from Crypto.Hash import SHA
from Crypto.Util.Padding import pad, unpad
import hmac

class PassportDataUploader:
    def __init__(self):
        self.connection = None
        self.data_dir = "generated_data"
        
        # BAC密钥
        self.kenc = None
        self.kmac = None
        self.ssc = None
        
        # 文件ID映射（基于FileSystem.java）
        self.file_ids = {
            'COM': 0x011E,    # EF_COM_FID
            'DG1': 0x0101,    # EF_DG1_FID
            'DG2': 0x0102,    # EF_DG2_FID
            'DG11': 0x010B,   # EF_DG11_FID
            'DG12': 0x010C,   # EF_DG12_FID
            'DG15': 0x010F,   # EF_DG15_FID
            'SOD': 0x011D,    # EF_SOD_FID
        }
        
        self.bin_files = {
            'COM': '011E.bin',
            'DG1': '0101.bin',
            'DG2': '0102.bin',
            'DG11': '010B.bin',
            'DG12': '010C.bin',
            'DG15': '010F.bin',
            'SOD': '011D.bin',
        }

    def connect_to_card(self):
        """连接到智能卡"""
        try:
            reader_list = readers()
            if not reader_list:
                print("错误：未找到读卡器")
                return False
            
            print(f"找到 {len(reader_list)} 个读卡器:")
            for i, reader in enumerate(reader_list):
                print(f"  {i}: {reader}")
            
            # 让用户选择读卡器
            if len(reader_list) > 1:
                print("\n请选择读卡器 (输入编号，默认0): ", end='')
                choice = input().strip()
                reader_idx = int(choice) if choice.isdigit() else 0
                reader_idx = min(reader_idx, len(reader_list) - 1)
            else:
                reader_idx = 0
            
            reader = reader_list[reader_idx]
            print(f"\n使用读卡器: {reader}")
            
            # 直接连接到指定的读卡器
            self.connection = reader.createConnection()
            self.connection.connect()
            
            atr = self.connection.getATR()
            print(f"连接成功，ATR: {toHexString(atr)}")
            
            # 分析ATR
            if atr:
                print(f"ATR长度: {len(atr)} 字节")
                if len(atr) > 0:
                    print("卡片已正确识别")
            
            return True
            
        except NoCardException:
            print("错误：未检测到智能卡")
            return False
        except Exception as e:
            print(f"连接失败: {e}")
            return False

    def send_apdu(self, apdu, description=""):
        """发送APDU命令"""
        try:
            print(f"发送{description}: {toHexString(apdu)}")
            response, sw1, sw2 = self.connection.transmit(apdu)
            print(f"响应: {toHexString(response)} SW: {sw1:02X}{sw2:02X}")
            
            if sw1 == 0x90 and sw2 == 0x00:
                return True, response
            elif sw1 == 0x61:  # 还有数据
                get_response = [0x00, 0xC0, 0x00, 0x00, sw2]
                response2, sw1, sw2 = self.connection.transmit(get_response)
                return sw1 == 0x90 and sw2 == 0x00, response + response2
            else:
                print(f"错误: SW={sw1:02X}{sw2:02X}")
                return False, response
                
        except Exception as e:
            print(f"APDU发送失败: {e}")
            return False, []

    def select_applet(self):
        """选择护照小程序"""
        print("\n=== 选择护照小程序 ===")
        # 使用ICAO LDS AID选择护照小程序
        aid = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]
        select_cmd = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid
        success, response = self.send_apdu(select_cmd, "选择护照小程序 (ICAO LDS)")
        return success

    def extract_mrz_from_dg1(self):
        """从DG1文件中提取MRZ数据用于BAC"""
        dg1_path = os.path.join(self.data_dir, '0101.bin')
        if not os.path.exists(dg1_path):
            print("错误：DG1文件不存在")
            return None, None, None
        
        with open(dg1_path, 'rb') as f:
            data = f.read()
        
        # 解析TLV结构，找到MRZ数据
        # DG1格式: 0x61 [length] 0x5F1F [length] [MRZ data]
        if data[0] != 0x61:
            print("错误：DG1格式不正确")
            return None, None, None
        
        # 跳过0x61的长度
        if data[1] & 0x80:
            length_bytes = data[1] & 0x7f
            value_start = 2 + length_bytes
        else:
            value_start = 2
        
        # 找到0x5F1F标签
        if data[value_start] == 0x5F and data[value_start+1] == 0x1F:
            mrz_start = value_start + 3  # 跳过标签和长度
            mrz_data = data[mrz_start:mrz_start+88]  # MRZ总长度88字节
            
            # 提取MRZ第二行数据（从第44字节开始）
            mrz_line2 = mrz_data[44:88].decode('ascii')
            
            # 解析文档号、出生日期、过期日期
            doc_number = mrz_line2[0:9]      # 护照号（9位）
            date_of_birth = mrz_line2[13:19] # 出生日期（6位）
            date_of_expiry = mrz_line2[21:27] # 过期日期（6位）
            
            print(f"从DG1提取的MRZ信息:")
            print(f"  文档号: {doc_number}")
            print(f"  出生日期: {date_of_birth}")
            print(f"  过期日期: {date_of_expiry}")
            
            return doc_number, date_of_birth, date_of_expiry
        
        return None, None, None

    def calculate_check_digit(self, data):
        """计算MRZ校验位"""
        weights = [7, 3, 1]
        total = 0
        for i, char in enumerate(data):
            if char.isdigit():
                val = int(char)
            elif char.isalpha():
                val = ord(char.upper()) - ord('A') + 10
            else:  # < character
                val = 0
            total += val * weights[i % 3]
        return str(total % 10)

    def derive_bac_keys(self, doc_number, date_of_birth, date_of_expiry):
        """从MRZ数据生成BAC密钥"""
        print("\n=== 生成BAC密钥 ===")
        
        # 计算校验位
        doc_check = self.calculate_check_digit(doc_number)
        dob_check = self.calculate_check_digit(date_of_birth)
        doe_check = self.calculate_check_digit(date_of_expiry)
        
        # 构建密钥种子
        key_seed = doc_number + doc_check + date_of_birth + dob_check + date_of_expiry + doe_check
        print(f"密钥种子: {key_seed}")
        
        # 计算SHA-1哈希
        h = SHA.new(key_seed.encode('ascii'))
        hash_result = h.digest()
        
        # 取前16字节作为密钥种子
        k_seed = hash_result[:16]
        
        # 生成加密密钥（Kenc）
        d_enc = k_seed + b'\x00\x00\x00\x01'
        h_enc = SHA.new(d_enc)
        k_enc = h_enc.digest()[:16]
        
        # 生成MAC密钥（Kmac）
        d_mac = k_seed + b'\x00\x00\x00\x02'
        h_mac = SHA.new(d_mac)
        k_mac = h_mac.digest()[:16]
        
        # 调整奇偶校验位
        self.kenc = self.adjust_parity(k_enc)
        self.kmac = self.adjust_parity(k_mac)
        
        print(f"Kenc: {hexlify(self.kenc).decode()}")
        print(f"Kmac: {hexlify(self.kmac).decode()}")
        
        return True

    def adjust_parity(self, key):
        """调整DES密钥的奇偶校验位"""
        adjusted = bytearray(key)
        for i in range(len(adjusted)):
            byte = adjusted[i]
            # 计算1的个数
            count = bin(byte).count('1')
            if count % 2 == 0:
                # 如果是偶数个1，翻转最低位
                adjusted[i] ^= 0x01
        return bytes(adjusted)

    def perform_bac(self):
        """执行BAC认证"""
        print("\n=== 执行BAC认证 ===")
        
        # Step 1: GET_CHALLENGE获取随机数
        get_challenge = [0x00, 0x84, 0x00, 0x00, 0x08]
        success, rnd_icc = self.send_apdu(get_challenge, "GET_CHALLENGE")
        if not success or len(rnd_icc) != 8:
            print("获取挑战失败")
            return False
        
        print(f"RND.ICC: {hexlify(bytes(rnd_icc)).decode()}")
        
        # Step 2: 生成随机数和密钥材料
        import random
        rnd_ifd = bytes([random.randint(0, 255) for _ in range(8)])
        k_ifd = bytes([random.randint(0, 255) for _ in range(16)])
        
        print(f"RND.IFD: {hexlify(rnd_ifd).decode()}")
        print(f"K.IFD: {hexlify(k_ifd).decode()}")
        
        # Step 3: 构建并加密数据
        # S = RND.IFD || RND.ICC || K.IFD
        s = rnd_ifd + bytes(rnd_icc) + k_ifd
        
        # 用Kenc加密S
        cipher = DES3.new(self.kenc, DES3.MODE_CBC, iv=b'\x00'*8)
        e_ifd = cipher.encrypt(s)
        
        # 计算MAC (ISO9797-1 M2 + Retail MAC Alg.3)
        m_ifd = self.iso9797_mac_alg3_m2(self.kmac, e_ifd)
        
        print(f"E.IFD: {hexlify(e_ifd).decode()}")
        print(f"M.IFD: {hexlify(m_ifd).decode()}")
        
        # Step 4: 发送EXTERNAL_AUTHENTICATE
        # cmd_data = E.IFD || M.IFD
        cmd_data = e_ifd + m_ifd
        
        external_auth = [0x00, 0x82, 0x00, 0x00, len(cmd_data)] + list(cmd_data)
        success, response = self.send_apdu(external_auth, "EXTERNAL_AUTHENTICATE")
        
        if not success or len(response) != 40:
            print("外部认证失败")
            return False
        
        # Step 5: 验证响应并建立会话密钥
        e_icc = bytes(response[:32])
        m_icc = bytes(response[32:40])
        
        # 验证MAC (与卡侧相同算法)
        mac_check = self.iso9797_mac_alg3_m2(self.kmac, e_icc)
        
        if mac_check != m_icc:
            print("MAC验证失败")
            return False
        
        # 解密E.ICC
        cipher = DES3.new(self.kenc, DES3.MODE_CBC, iv=b'\x00'*8)
        r = cipher.decrypt(e_icc)
        
        # R = RND.ICC || RND.IFD || K.ICC
        rnd_icc_check = r[0:8]
        rnd_ifd_check = r[8:16]
        k_icc = r[16:32]
        
        if rnd_icc_check != bytes(rnd_icc) or rnd_ifd_check != rnd_ifd:
            print("随机数验证失败")
            return False
        
        print("BAC认证成功！")
        
        # Step 6: 生成会话密钥
        # K_seed = K.IFD XOR K.ICC
        k_seed_session = bytes(a ^ b for a, b in zip(k_ifd, k_icc))
        
        # 生成会话加密密钥
        d_enc_session = k_seed_session + b'\x00\x00\x00\x01'
        h_enc_session = SHA.new(d_enc_session)
        self.kenc_session = self.adjust_parity(h_enc_session.digest()[:16])
        
        # 生成会话MAC密钥
        d_mac_session = k_seed_session + b'\x00\x00\x00\x02'
        h_mac_session = SHA.new(d_mac_session)
        self.kmac_session = self.adjust_parity(h_mac_session.digest()[:16])
        
        # 计算SSC（Send Sequence Counter）
        self.ssc = bytes(rnd_icc[4:8]) + bytes(rnd_ifd[4:8])
        
        print(f"会话Kenc: {hexlify(self.kenc_session).decode()}")
        print(f"会话Kmac: {hexlify(self.kmac_session).decode()}")
        print(f"SSC: {hexlify(self.ssc).decode()}")
        
        return True

    def iso9797_mac_alg3_m2(self, key16, data: bytes) -> bytes:
        """计算ISO9797-1 Padding Method 2 + Retail MAC (Alg.3) 8字节MAC
        - key16: 16字节(2-Key 3DES) K1||K2
        - data: 原始数据，内部按M2进行0x80 00..填充
        """
        if len(key16) != 16:
            raise ValueError("Kmac长度必须为16字节(2-Key 3DES)")

        k1 = key16[:8]
        k2 = key16[8:16]

        # M2填充：追加0x80，再补0x00至8字节对齐（即使本身已对齐也要加一整块）
        pad_len = (8 - ((len(data) + 1) % 8)) % 8
        padded = data + b"\x80" + (b"\x00" * pad_len)

        # 先用K1做DES-CBC得到最后一块
        des_cbc_k1 = DES.new(k1, DES.MODE_CBC, iv=b"\x00" * 8)
        y = des_cbc_k1.encrypt(padded)[-8:]

        # 再用K2做DES解密，然后用K1做DES加密
        des_ecb_k2 = DES.new(k2, DES.MODE_ECB)
        t = des_ecb_k2.decrypt(y)
        des_ecb_k1 = DES.new(k1, DES.MODE_ECB)
        mac8 = des_ecb_k1.encrypt(t)
        return mac8

    def set_mrz_for_bac(self, doc_number, date_of_birth, date_of_expiry):
        """通过PUT_DATA设置MRZ数据（用于初始化BAC密钥）"""
        print("\n=== 设置MRZ数据（初始化） ===")
        
        # 构建MRZ TLV数据（MRZ_TAG = 0x62）
        # 内部包含三个TLV：文档号、出生日期、过期日期
        doc_tlv = bytes([0x04, len(doc_number)]) + doc_number.encode('ascii')
        dob_tlv = bytes([0x04, len(date_of_birth)]) + date_of_birth.encode('ascii')
        doe_tlv = bytes([0x04, len(date_of_expiry)]) + date_of_expiry.encode('ascii')
        
        # 组合内部数据
        inner_data = doc_tlv + dob_tlv + doe_tlv
        
        # 包装成0x62标签
        mrz_data = bytes([0x62, len(inner_data)]) + inner_data
        
        # PUT_DATA APDU: 00 DA 00 62 [length] [data...]
        apdu = [0x00, 0xDA, 0x00, 0x62, len(mrz_data)] + list(mrz_data)
        
        success, response = self.send_apdu(apdu, "PUT_DATA设置MRZ")
        if success:
            print("MRZ数据设置成功，BAC密钥已初始化")
        return success

    def create_file(self, file_id, size):
        """创建文件（不需要BAC）"""
        print(f"\n=== 创建文件 0x{file_id:04X} (大小: {size}) ===")
        
        # CREATE FILE APDU: 00 E0 00 00 06 63 04 [size_high] [size_low] [fid_high] [fid_low]
        apdu = [0x00, 0xE0, 0x00, 0x00, 0x06,
                0x63, 0x04,
                (size >> 8) & 0xFF, size & 0xFF,
                (file_id >> 8) & 0xFF, file_id & 0xFF]
        
        success, response = self.send_apdu(apdu, f"CREATE_FILE 0x{file_id:04X}")
        return success

    def select_file(self, file_id):
        """选择文件"""
        print(f"\n=== 选择文件 0x{file_id:04X} ===")
        
        # SELECT FILE APDU: 00 A4 00 00 02 [fid_high] [fid_low]
        apdu = [0x00, 0xA4, 0x00, 0x00, 0x02,
                (file_id >> 8) & 0xFF, file_id & 0xFF]
        
        success, response = self.send_apdu(apdu, f"SELECT_FILE 0x{file_id:04X}")
        return success

    def update_binary(self, offset, data):
        """更新二进制文件数据（不需要BAC）"""
        print(f"=== 更新数据 (偏移: {offset}, 长度: {len(data)}) ===")
        
        # 分块发送数据（每次最大200字节）
        chunk_size = 200
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            current_offset = offset + i
            
            # UPDATE BINARY APDU: 00 D6 [offset_high] [offset_low] [length] [data...]
            apdu = [0x00, 0xD6,
                    (current_offset >> 8) & 0xFF, current_offset & 0xFF,
                    len(chunk)] + list(chunk)
            
            success, response = self.send_apdu(apdu, f"UPDATE_BINARY块 {i//chunk_size + 1}")
            if not success:
                return False
        
        return True

    def upload_file_data(self, file_type, filepath):
        """上传单个文件的数据"""
        if not os.path.exists(filepath):
            print(f"文件不存在: {filepath}")
            return False
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        print(f"\n{'='*50}")
        print(f"上传 {file_type} 文件")
        print(f"文件: {filepath}")
        print(f"大小: {len(data)} 字节")
        print(f"{'='*50}")
        
        file_id = self.file_ids[file_type]
        
        # 1. 创建文件 - 为SOD文件分配更大内存
        if file_type == 'SOD':
            # 为SOD文件分配更大的内存空间（原文件大小 + 1000字节缓冲，或最少2500字节）
            sod_memory_size = max(len(data) + 1000, 2500)
            print(f"🔧 为SOD文件分配额外内存: {sod_memory_size} 字节 (原始大小: {len(data)} 字节)")
            if not self.create_file(file_id, sod_memory_size):
                print(f"创建文件 {file_type} 失败")
                return False
        else:
            # 其他文件按实际大小分配
            if not self.create_file(file_id, len(data)):
                print(f"创建文件 {file_type} 失败")
                return False
        
        # 2. 选择文件
        if not self.select_file(file_id):
            print(f"选择文件 {file_type} 失败")
            return False
        
        # 3. 写入数据
        if not self.update_binary(0, data):
            print(f"更新文件 {file_type} 数据失败")
            return False
        
        print(f"✓ 文件 {file_type} 上传成功!")
        return True

    def lock_applet(self):
        """锁定小程序（可选）"""
        print("\n=== 锁定小程序 ===")
        # PUT_DATA with P1=0xDE P2=0xAD sets LOCKED state
        apdu = [0x00, 0xDA, 0xDE, 0xAD, 0x00]
        success, response = self.send_apdu(apdu, "锁定小程序")
        if success:
            print("小程序已锁定")
        return success

    def upload_aa_private_key(self):
        """上传AA私钥到智能卡 - 修复AA认证失败问题"""
        print("\n" + "="*60)
        print("🔐 上传AA私钥（修复AA认证失败）")
        print("="*60)
        
        # 从生成器获取私钥
        from generate_all_passport_data import PassportDataGenerator
        generator = PassportDataGenerator()
        private_key = generator.private_key
        
        # 获取RSA私钥的模数和指数
        private_numbers = private_key.private_numbers()
        modulus = private_numbers.public_numbers.n
        private_exponent = private_numbers.d
        
        # 转换为字节数组（大端序）
        key_size_bytes = private_key.key_size // 8
        modulus_bytes = modulus.to_bytes(key_size_bytes, byteorder='big')
        exponent_bytes = private_exponent.to_bytes(key_size_bytes, byteorder='big')
        
        print(f"🔑 RSA密钥大小: {private_key.key_size} bits")
        print(f"📏 模数长度: {len(modulus_bytes)} 字节")
        print(f"📏 指数长度: {len(exponent_bytes)} 字节")
        
        # 构建BER-TLV: 60 00 | 04 <len> <value> 与 61 00 | 04 <len> <value>
        # 先尝试长度编码 81 80（128）
        modulus_container_81 = bytes([0x60, 0x00, 0x04, 0x81, 0x80]) + modulus_bytes
        exponent_container_81 = bytes([0x61, 0x00, 0x04, 0x81, 0x80]) + exponent_bytes

        # 先发指数再发模数（尝试不同顺序）
        success2 = self.send_put_data_raw(0x00, 0x61, exponent_container_81, "AA私钥指数(81)")
        success1 = self.send_put_data_raw(0x00, 0x60, modulus_container_81, "AA私钥模数(81)")

        # 若失败，尝试长度编码 82 00 80（128）
        if not (success1 and success2):
            modulus_container_82 = bytes([0x60, 0x00, 0x04, 0x82, 0x00, 0x80]) + modulus_bytes
            exponent_container_82 = bytes([0x61, 0x00, 0x04, 0x82, 0x00, 0x80]) + exponent_bytes
            success2 = self.send_put_data_raw(0x00, 0x61, exponent_container_82, "AA私钥指数(82)")
            success1 = self.send_put_data_raw(0x00, 0x60, modulus_container_82, "AA私钥模数(82)")
        
        if success1 and success2:
            print("✅ AA私钥上传成功 - AA认证问题已修复!")
            return True
        else:
            print("❌ AA私钥上传失败")
            return False
    
    def encode_tlv(self, tag, value):
        """TLV编码辅助函数"""
        # 处理tag
        if tag <= 0xFF:
            tag_bytes = bytes([tag])
        elif tag <= 0xFFFF:
            tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF])
        else:
            tag_bytes = bytes([(tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF])
        
        # 处理length
        length = len(value)
        if length < 128:
            length_bytes = bytes([length])
        elif length < 256:
            length_bytes = bytes([0x81, length])
        else:
            length_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        
        return tag_bytes + length_bytes + value
    
    def send_put_data_raw(self, p1, p2, data, description):
        """发送PUT DATA命令（原始格式，适用于AA私钥）"""
        try:
            print(f"📤 发送{description}: {len(data)} 字节")
            
            # 构建PUT DATA命令: 00 DA P1 P2 Lc [data]
            apdu = [0x00, 0xDA, p1, p2, len(data)] + list(data)
            response, sw1, sw2 = self.connection.transmit(apdu)
            
            if sw1 == 0x90 and sw2 == 0x00:
                print(f"✅ {description}上传成功")
                return True
            else:
                print(f"❌ {description}上传失败: {sw1:02X}{sw2:02X}")
                if sw1 == 0x6F and sw2 == 0x00:
                    print("💡 错误分析: Wrong file - TLV格式可能不正确")
                elif sw1 == 0x69 and sw2 == 0x82:
                    print("💡 错误分析: Security status not satisfied")
                elif sw1 == 0x6A and sw2 == 0x86:
                    print("💡 错误分析: Incorrect parameters P1-P2")
                return False
                
        except Exception as e:
            print(f"❌ {description}上传异常: {e}")
            return False
    
    def upload_data_apdu(self, p1, p2, data, description):
        """发送PUT DATA命令的通用方法"""
        try:
            # 分块传输大数据
            max_chunk = 200
            if len(data) <= max_chunk:
                # 单块传输
                apdu = [0x00, 0xDA, p1, p2, len(data)] + list(data)
                response, sw1, sw2 = self.connection.transmit(apdu)
                
                if sw1 == 0x90 and sw2 == 0x00:
                    print(f"✅ {description}上传成功")
                    return True
                else:
                    print(f"❌ {description}上传失败: {sw1:02X}{sw2:02X}")
                    return False
            else:
                # 多块传输
                chunks = [data[i:i+max_chunk] for i in range(0, len(data), max_chunk)]
                print(f"📦 {description}分为 {len(chunks)} 个数据块上传")
                
                for i, chunk in enumerate(chunks):
                    # 使用不同的P2标识不同块
                    apdu = [0x00, 0xDA, p1, p2 + i, len(chunk)] + list(chunk)
                    response, sw1, sw2 = self.connection.transmit(apdu)
                    
                    if sw1 == 0x90 and sw2 == 0x00:
                        print(f"✅ {description}块 {i+1}/{len(chunks)} 上传成功")
                    else:
                        print(f"❌ {description}块 {i+1} 上传失败: {sw1:02X}{sw2:02X}")
                        return False
                
                return True
                
        except Exception as e:
            print(f"❌ {description}上传异常: {e}")
            return False

    def upload_all_files(self):
        """正确的上传流程 - 修复版本"""
        if not self.connect_to_card():
            return False
        
        try:
            # Step 1: 选择小程序
            print("\n" + "="*60)
            print("Step 1: 选择小程序")
            print("="*60)
            if not self.select_applet():
                print("选择小程序失败")
                return False
            
            # Step 2: 从DG1提取MRZ数据
            print("\n" + "="*60)
            print("Step 2: 从DG1提取MRZ数据")
            print("="*60)
            doc_number, date_of_birth, date_of_expiry = self.extract_mrz_from_dg1()
            if not doc_number:
                print("无法从DG1提取MRZ数据，使用默认值")
                doc_number = "E5WX43648"  # 9位
                date_of_birth = "910825"   # 6位
                date_of_expiry = "320629"   # 6位
            
            # Step 3: 初始化MRZ数据（如果需要）
            print("\n" + "="*60)
            print("Step 3: 初始化MRZ数据（设置BAC密钥）")
            print("="*60)
            print("注意：如果卡已经初始化过，这一步可能失败")
            self.set_mrz_for_bac(doc_number, date_of_birth, date_of_expiry)
            
            # Step 4: 上传AA私钥（修复AA认证失败的关键步骤）
            aa_success = self.upload_aa_private_key()
            
            # Step 5: 创建所有文件（不需要BAC）
            print("\n" + "="*60)
            print("Step 5: 创建所有文件")
            print("="*60)
            
            upload_order = ['COM', 'DG1', 'DG2', 'DG11', 'DG12', 'DG15', 'SOD']
            
            for file_type in upload_order:
                bin_file = self.bin_files[file_type]
                filepath = os.path.join(self.data_dir, bin_file)
                
                if not self.upload_file_data(file_type, filepath):
                    print(f"上传 {file_type} 失败")
                    # 继续尝试其他文件
                
                time.sleep(0.1)  # 短暂延迟
            
            # Step 5: （可选）锁定小程序
            print("\n" + "="*60)
            print("Step 5: 锁定小程序（可选）")
            print("="*60)
            print("警告：锁定后将无法再修改数据！")
            print("是否锁定小程序？(y/n): ", end='')
            if input().lower() == 'y':
                self.lock_applet()
            
            print("\n" + "="*60)
            print("数据上传完成！")
            print("="*60)
            
            # Step 6: 测试BAC认证（验证）
            print("\n" + "="*60)
            print("Step 6: 测试BAC认证")
            print("="*60)
            
            # 生成BAC密钥
            if self.derive_bac_keys(doc_number, date_of_birth, date_of_expiry):
                # 执行BAC认证
                if self.perform_bac():
                    print("\n✓ BAC认证测试成功！")
                    print("护照数据已正确写入并可以通过BAC认证访问")
                else:
                    print("\n✗ BAC认证测试失败")
                    print("数据已写入，但BAC认证可能需要重新初始化")
            
            return True
            
        except Exception as e:
            print(f"上传过程中出错: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if self.connection:
                self.connection.disconnect()

def main():
    print("护照数据上传工具（正确版本）")
    print("="*60)
    print("基于Java代码分析的正确上传流程：")
    print("1. 选择小程序")
    print("2. 设置MRZ数据（初始化BAC密钥）") 
    print("3. 创建并上传所有文件")
    print("4. （可选）锁定小程序")
    print("5. 测试BAC认证")
    print("="*60)
    
    uploader = PassportDataUploader()
    
    # 检查生成的数据文件
    if not os.path.exists(uploader.data_dir):
        print(f"错误：数据目录 {uploader.data_dir} 不存在")
        print("请先运行 generate_passport_data.py 生成数据文件")
        return
    
    # 检查所有必要的文件
    missing_files = []
    for file_type, bin_file in uploader.bin_files.items():
        filepath = os.path.join(uploader.data_dir, bin_file)
        if not os.path.exists(filepath):
            missing_files.append(bin_file)
    
    if missing_files:
        print("错误：以下文件缺失:")
        for file in missing_files:
            print(f"  {file}")
        print("请先运行 generate_passport_data.py 生成所有数据文件")
        return
    
    # 开始上传
    print("\n请确保智能卡已插入读卡器...")
    print("警告：这将覆盖卡上的现有数据！")
    input("按回车键开始上传...")
    
    if uploader.upload_all_files():
        print("\n上传成功完成！")
    else:
        print("\n上传过程中出现错误")

if __name__ == '__main__':
    main()