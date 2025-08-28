#!/usr/bin/env python3
"""
完整护照数据生成脚本
整合COM, DG1, DG2, DG11, DG12, DG15, SOD生成
"""

import os
import hashlib
from PIL import Image
import io
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from asn1crypto import cms as asn1_cms, algos as asn1_algos, core as asn1_core, x509 as asn1_x509

class PassportDataGenerator:
    def __init__(self):
        # 正确的护照信息 [[memory:6844710]]
        self.passport_info = {
            'passport_number': 'E5WX43648',  # 9位护照号
            'date_of_birth': '910825',       # YYMMDD
            'date_of_expiry': '320629',      # YYMMDD  
            'nationality': 'ARE',
            'sex': 'M',
            'surname': 'SAMARA',
            'given_names': 'NOUR'
        }
        
        # 生成RSA密钥对（用于DG15和SOD）
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # 输出目录
        self.output_dir = 'generated_data'
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def encode_tlv(self, tag, value):
        """TLV编码"""
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
    
    def generate_com(self):
        """生成COM文件 (0x011E)
        规范：
        - 5F01 LDS version: '0107'
        - 5F36 Unicode version: '040000'
        - 5C  Data Group presence list: 按升序列出存在的DG编号
          我们实际写入 DG1, DG2, DG11, DG12, DG15, SOD(=0x1D)
        """
        lds_version = b'0107'
        unicode_version = b'040000'
        # 按规范，5C为“Tag List”，应填写各DG的TLV标签值而非编号
        # 我们存在的DG：DG1(0x61), DG2(0x75), DG11(0x6B), DG12(0x6C), DG15(0x6F), SOD(0x77)
        # 升序排列：61, 6B, 6C, 6F, 75, 77
        dg_list = bytes([0x61, 0x6B, 0x6C, 0x6F, 0x75, 0x77])
        
        content = self.encode_tlv(0x5F01, lds_version)
        content += self.encode_tlv(0x5F36, unicode_version)
        content += self.encode_tlv(0x5C, dg_list)
        
        return self.encode_tlv(0x60, content)
    
    def generate_dg1(self):
        """生成DG1文件 (0x0101) - MRZ数据"""
        # MRZ第一行：44字符
        mrz_line1 = 'P<ARESAMARA<<NOUR<<<<<<<<<<<<<<<<<<<<<<<<<<<'
        # MRZ第二行：44字符 - 使用正确格式 [[memory:6844710]]
        mrz_line2 = 'E5WX436483ARE9108253M3206294<<<<<<<<<<<<<<00'
        
        mrz_data = (mrz_line1 + mrz_line2).encode('ascii')
        mrz_tlv = self.encode_tlv(0x5F1F, mrz_data)
        return self.encode_tlv(0x61, mrz_tlv)
    
    def generate_dg2(self):
        """生成DG2文件 (0x0102) - 人脸图像"""
        # 优先使用模板方法，如果模板不存在则使用标准方法
        template_path = 'old/0102.bin'
        if os.path.exists(template_path):
            print("使用模板文件生成DG2")
            return self._generate_dg2_from_template()
        else:
            print("使用标准方法生成DG2（无需模板文件）")
            return self._generate_dg2_legacy()
    
    def _generate_dg2_from_template(self):
        """基于原始DG2文件模板生成新的DG2，只替换JPEG数据"""
        # 读取原始DG2文件作为模板
        template_path = 'old/0102.bin'
        if not os.path.exists(template_path):
            print(f"警告：未找到模板文件 {template_path}，使用默认生成方法")
            return self._generate_dg2_legacy()
        
        with open(template_path, 'rb') as f:
            template_data = f.read()
        
        # 读取新的JPEG图像
        image_path = '1.jpg'
        if os.path.exists(image_path):
            with open(image_path, 'rb') as f:
                new_jpeg_data = f.read()
        else:
            print(f"警告：未找到图像文件 {image_path}，使用默认图像")
            # 创建默认图像（413x531像素）
            img = Image.new('RGB', (413, 531), color='white')
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=95)
            new_jpeg_data = buffer.getvalue()
        
        # 查找模板中JPEG数据的位置
        jpeg_start = -1
        for i in range(len(template_data) - 1):
            if template_data[i] == 0xFF and template_data[i+1] == 0xD8:
                jpeg_start = i
                break
        
        if jpeg_start == -1:
            print("错误：模板文件中未找到JPEG数据")
            return self._generate_dg2_legacy()
        
        # 查找JPEG结束位置
        jpeg_end = -1
        for i in range(jpeg_start + 2, len(template_data) - 1):
            if template_data[i] == 0xFF and template_data[i+1] == 0xD9:
                jpeg_end = i + 2
                break
        
        if jpeg_end <= jpeg_start:
            print("错误：模板文件中JPEG数据不完整")
            return self._generate_dg2_legacy()
        
        # 构建新的DG2文件
        before_jpeg = template_data[:jpeg_start]
        after_jpeg = template_data[jpeg_end:]
        new_dg2_data = before_jpeg + new_jpeg_data + after_jpeg
        
        # 更新长度字段
        new_dg2_data = self._update_dg2_lengths(new_dg2_data, len(new_jpeg_data) - (jpeg_end - jpeg_start))
        
        print(f"✅ DG2生成成功：{len(new_dg2_data)} 字节（包含 {len(new_jpeg_data)} 字节JPEG数据）")
        return new_dg2_data
    
    def _update_dg2_lengths(self, data, size_diff):
        """更新DG2文件中的长度字段"""
        data = bytearray(data)
        
        # 更新主长度字段（偏移2-3）
        if len(data) >= 4 and data[0] == 0x75 and data[1] == 0x82:
            current_length = (data[2] << 8) | data[3]
            new_length = current_length + size_diff
            data[2] = (new_length >> 8) & 0xFF
            data[3] = new_length & 0xFF
        
        # 更新7F61长度字段（偏移6-7）
        if len(data) >= 8 and data[4] == 0x7F and data[5] == 0x61 and data[6] == 0x82:
            current_length = (data[7] << 8) | data[8]
            new_length = current_length + size_diff
            data[7] = (new_length >> 8) & 0xFF
            data[8] = new_length & 0xFF
        
        # 更新7F60长度字段（偏移12-13）
        if len(data) >= 16 and data[12] == 0x7F and data[13] == 0x60 and data[14] == 0x82:
            current_length = (data[15] << 8) | data[16]
            new_length = current_length + size_diff
            data[15] = (new_length >> 8) & 0xFF
            data[16] = new_length & 0xFF
        
        # 更新5F2E长度字段（寻址7F60内部）
        # 兼容旧模板：若模板中CBEFF头14-15/18-19为0，重新计算并回填
        i = 0
        # 定位7F61
        if len(data) >= 4 and data[0] == 0x75:
            # 跳过75长度
            if data[1] & 0x80:
                n = data[1] & 0x7F
                i = 2 + n
            else:
                i = 2
        # 找7F61
        while i + 4 < len(data) and not (data[i] == 0x7F and data[i+1] == 0x61):
            i += 1
        if i + 4 < len(data):
            # 读7F61长度
            j = i + 2
            if data[j] & 0x80:
                n = data[j] & 0x7F
                j += 1 + n
            else:
                j += 1
            # optional count 0x02 ...
            if j + 2 < len(data) and data[j] == 0x02:
                # skip INTEGER
                if data[j+1] & 0x80:
                    n = data[j+1] & 0x7F
                    j += 2 + n + data[j+2]
                else:
                    j += 2 + data[j+1]
            # 找7F60
            if j + 4 < len(data) and data[j] == 0x7F and data[j+1] == 0x60:
                k = j + 2
                # 跳过7F60长度
                if data[k] & 0x80:
                    n = data[k] & 0x7F
                    k += 1 + n
                else:
                    k += 1
                # 现在应处于孩子TLV，查找5F2E
                p = k
                while p + 5 < len(data):
                    if data[p] == 0x5F and data[p+1] == 0x2E:
                        # 读5F2E长度
                        if data[p+2] & 0x80:
                            n = data[p+2] & 0x7F
                            old_len = 0
                            for t in range(n):
                                old_len = (old_len << 8) | data[p+3+t]
                            new_len = old_len + size_diff
                            # 写回同样的长度字节数
                            for t in range(n):
                                data[p+3+n-1-t] = (new_len >> (8*t)) & 0xFF
                            bio_off = p + 3 + n
                        else:
                            old_len = data[p+2]
                            new_len = (old_len + size_diff) & 0xFF
                            data[p+2] = new_len
                            bio_off = p + 3
                        # 修正CBEFF头14-15、18-19
                        if bio_off + 50 <= len(data):
                            total_bio_length = (old_len + size_diff)
                            data[bio_off + 14] = (total_bio_length >> 8) & 0xFF
                            data[bio_off + 15] = total_bio_length & 0xFF
                            rec_len = (total_bio_length - 14)
                            data[bio_off + 18] = (rec_len >> 8) & 0xFF
                            data[bio_off + 19] = rec_len & 0xFF
                        break
                    p += 1
        
        return bytes(data)
    
    def _generate_dg2_legacy(self):
        """标准DG2生成方法（不依赖模板文件）"""
        # 读取JPEG图像
        image_path = '1.jpg'
        if os.path.exists(image_path):
            with open(image_path, 'rb') as f:
                jpeg_data = f.read()
        else:
            # 创建默认图像（413x531像素）
            img = Image.new('RGB', (413, 531), color='white')
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=95)
            jpeg_data = buffer.getvalue()
        
        # 标准CBEFF头部（50字节）- 基于真实DG2分析
        cbeff_header = bytes([
            0x46, 0x41, 0x43, 0x00,  # "FAC\0" - 人脸类型标识
            0x30, 0x31, 0x30, 0x00,  # "010\0" - 版本
            0x00, 0x00, 0x00, 0x00,  # 保留字段
            0x00, 0x00, 0x3D, 0x1C,  # 数据长度（会动态更新）
            0x00, 0x01, 0x00, 0x00,  # 记录数量
            0x3D, 0x0E, 0x00, 0x00,  # 第一个记录长度（会动态更新）
            0x00, 0x00, 0x00, 0x00,  # 保留
            0x00, 0x00, 0x00, 0x00,  # 保留
            0x00, 0x00, 0x00, 0x00,  # 保留
            0x00, 0x00, 0x00, 0x00,  # 保留
            0x01, 0x62, 0x02, 0x16,  # 格式标识符
            0x00, 0x00, 0x00, 0x00,  # 保留
            0x00, 0x00              # 保留
        ])
        
        # 动态更新CBEFF头部中的长度字段
        total_bio_length = len(cbeff_header) + len(jpeg_data)
        cbeff_header = bytearray(cbeff_header)
        cbeff_header[14] = (total_bio_length >> 8) & 0xFF  # 高字节
        cbeff_header[15] = total_bio_length & 0xFF         # 低字节
        # 修正：JMRTD对人脸CBEFF记录的内部长度校验需要 record_len = total_bio_length - 14
        # 之前使用 -12 会触发 "dataLength = -14" 的差值错误
        cbeff_header[18] = ((total_bio_length - 14) >> 8) & 0xFF  # 记录长度高字节
        cbeff_header[19] = (total_bio_length - 14) & 0xFF         # 记录长度低字节
        cbeff_header = bytes(cbeff_header)
        
        # 组合生物特征数据
        biometric_data = cbeff_header + jpeg_data
        
        # 构建标准TLV结构
        # 1. Biometric Type (A1标签) - 模板信息在前，兼容读取方的“模板标签”期望
        a1_content = bytes([
            0x81, 0x01, 0x02,        # 生物特征类型：人脸(02)
            0x82, 0x01, 0x00,        # 生物特征子类型
            0x87, 0x02, 0x01, 0x01,  # 创建日期和时间（占位）
            0x88, 0x02, 0x00, 0x08   # 有效期（占位）
        ])
        a1_tlv = self.encode_tlv(0xA1, a1_content)

        # 2. Biometric Data (5F2E标签)
        bio_5f2e = self.encode_tlv(0x5F2E, biometric_data)

        # 3. Biometric Data Block (7F60标签) = A1 + 5F2E
        bio_7f60 = self.encode_tlv(0x7F60, a1_tlv + bio_5f2e)
        
        # 4. Biometric Information Template (7F61标签)
        # 包含实例数量 + BDB
        instance_data = bytes([0x02, 0x01, 0x01]) + bio_7f60  # 数量=1
        bio_7f61 = self.encode_tlv(0x7F61, instance_data)
        
        # 5. 最外层DG2标签 (75)
        return self.encode_tlv(0x75, bio_7f61)
    
    def generate_dg11(self):
        """生成DG11文件 (0x010B) - 额外个人信息"""
        # 姓名
        full_name = f"{self.passport_info['surname']}<<{self.passport_info['given_names']}"
        name_tlv = self.encode_tlv(0x5F0E, full_name.encode('ascii'))
        
        # 出生日期
        dob_tlv = self.encode_tlv(0x5F2B, b'19910825')
        
        # 地址（DUBAI）
        address_tlv = self.encode_tlv(0x5F11, b'DUBAI')
        
        # 标签列表
        content = self.encode_tlv(0x5C, bytes([0x5F, 0x0E, 0x5F, 0x2B, 0x5F, 0x11]))
        content += name_tlv + dob_tlv + address_tlv
        
        return self.encode_tlv(0x6B, content)
    
    def generate_dg12(self):
        """生成DG12文件 (0x010C) - 额外文档信息"""
        issue_date = self.encode_tlv(0x5F26, b'20220701')
        issuing_auth = self.encode_tlv(0x5F19, b'')
        personalization = self.encode_tlv(0x5F55, bytes([0x20, 0x22, 0x07, 0x01, 0x12, 0x00, 0x00]))
        
        content = self.encode_tlv(0x5C, bytes([0x5F, 0x19, 0x5F, 0x26, 0x5F, 0x55]))
        content += issuing_auth + issue_date + personalization
        
        return self.encode_tlv(0x6C, content)
    
    def generate_dg15(self):
        """生成DG15文件 (0x010F) - Active Authentication公钥"""
        # 获取公钥字节
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 包装成DG15格式
        return self.encode_tlv(0x6F, public_key_bytes)
    
    def generate_certificate(self):
        """生成自签名X.509证书（用于SOD）"""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MOI"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "EPASS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "UAE CSCA 01"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.public_key
        ).serial_number(
            115  # 0x73
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.public_key),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(self.private_key, hashes.SHA256(), backend=default_backend())
        
        return cert.public_bytes(serialization.Encoding.DER)
    
    def generate_sod(self):
        """生成SOD文件 (0x011D) - 标准CMS(PKCS#7) SignedData，DER严格编码"""
        # 1) 生成/收集需要签名的DG，并计算SHA-256哈希（LDS v1.7）
        dg_hashes = {}
        dg1_data = self.generate_dg1()
        dg2_data = self.generate_dg2()
        dg11_data = self.generate_dg11()
        dg12_data = self.generate_dg12()
        dg15_data = self.generate_dg15()
        dg_hashes[1] = hashlib.sha256(dg1_data).digest()
        dg_hashes[2] = hashlib.sha256(dg2_data).digest()
        dg_hashes[11] = hashlib.sha256(dg11_data).digest()
        dg_hashes[12] = hashlib.sha256(dg12_data).digest()
        dg_hashes[15] = hashlib.sha256(dg15_data).digest()
        
        # 2) 构造 LDS Security Object (DER) —— 手工DER，确保长度正确
        def der_len(n: int) -> bytes:
            if n < 0x80:
                return bytes([n])
            elif n < 0x100:
                return bytes([0x81, n])
            else:
                return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

        version = b"\x02\x01\x00"  # INTEGER 0
        # AlgorithmIdentifier for sha256: SEQ { OID sha256 }
        sha256_oid = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
        digest_alg = b"\x30" + der_len(len(sha256_oid)) + sha256_oid

        # DataGroupHashValues: SEQUENCE OF SEQUENCE { INTEGER dg, OCTET STRING hash }
        dg_seq_items = b""
        for dg_num, dg_hash in sorted(dg_hashes.items()):
            item = b"\x02\x01" + bytes([dg_num]) + b"\x04\x20" + dg_hash
            dg_seq_items += b"\x30" + der_len(len(item)) + item
        dg_seq = b"\x30" + der_len(len(dg_seq_items)) + dg_seq_items

        lds_so_inner = version + digest_alg + dg_seq
        lds_so_bytes = b"\x30" + der_len(len(lds_so_inner)) + lds_so_inner

        # 3) 证书（作为Document Signer）
        cert_der = self.generate_certificate()
        cert_asn1 = asn1_x509.Certificate.load(cert_der)

        # 4) 构造 SignedData（带签名属性：content-type、message-digest、signing-time）
        oid_lds_so = '2.23.136.1.1.1'  # id-icao-ldsSecurityObject

        # 签名属性
        from datetime import timezone
        signed_attrs = asn1_cms.CMSAttributes([
            asn1_cms.CMSAttribute({'type': 'content_type', 'values': [asn1_cms.ContentType(oid_lds_so)]}),
            asn1_cms.CMSAttribute({'type': 'message_digest', 'values': [asn1_core.OctetString(hashlib.sha256(lds_so_bytes).digest())]}),
            asn1_cms.CMSAttribute({'type': 'signing_time', 'values': [asn1_core.UTCTime(datetime.now(timezone.utc))]}),
        ])

        # 需要签名的DER就是signed_attrs本身
        to_be_signed = signed_attrs.dump()
        signature = self.private_key.sign(to_be_signed, padding.PKCS1v15(), hashes.SHA256())

        signer_info = asn1_cms.SignerInfo({
            'version': 'v1',
            'sid': asn1_cms.SignerIdentifier({
                'issuer_and_serial_number': asn1_cms.IssuerAndSerialNumber({
                    'issuer': cert_asn1.issuer if hasattr(cert_asn1, 'issuer') else cert_asn1['tbs_certificate']['issuer'],
                    'serial_number': cert_asn1.serial_number if hasattr(cert_asn1, 'serial_number') else cert_asn1['tbs_certificate']['serial_number']
                })
            }),
            'digest_algorithm': asn1_algos.DigestAlgorithm({'algorithm': 'sha256'}),
            'signed_attrs': signed_attrs,
            'signature_algorithm': asn1_algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
            'signature': signature,
        })

        from asn1crypto.core import ParsableOctetString
        signed_data = asn1_cms.SignedData({
            'version': 'v3',
            'digest_algorithms': [asn1_algos.DigestAlgorithm({'algorithm': 'sha256'})],
            'encap_content_info': asn1_cms.EncapsulatedContentInfo({
                'content_type': asn1_cms.ContentType(oid_lds_so),
                'content': ParsableOctetString(lds_so_bytes)
            }),
            'certificates': [asn1_cms.CertificateChoices(name='certificate', value=cert_asn1)],
            'signer_infos': [signer_info]
        })

        content_info = asn1_cms.ContentInfo({
            'content_type': 'signed_data',
            'content': signed_data
        })

        pkcs7_der = content_info.dump()
        # 包装成DG格式（0x77）
        return self.encode_tlv(0x77, pkcs7_der)
    
    def generate_all(self):
        """生成所有文件"""
        print("=== 生成护照数据文件 ===\n")
        
        # 生成COM
        com_data = self.generate_com()
        com_path = os.path.join(self.output_dir, '011E.bin')
        with open(com_path, 'wb') as f:
            f.write(com_data)
        print(f"✅ COM文件: {len(com_data)} 字节")
        
        # 生成DG1
        dg1_data = self.generate_dg1()
        dg1_path = os.path.join(self.output_dir, '0101.bin')
        with open(dg1_path, 'wb') as f:
            f.write(dg1_data)
        print(f"✅ DG1文件: {len(dg1_data)} 字节")
        
        # 生成DG2
        dg2_data = self.generate_dg2()
        dg2_path = os.path.join(self.output_dir, '0102.bin')
        with open(dg2_path, 'wb') as f:
            f.write(dg2_data)
        print(f"✅ DG2文件: {len(dg2_data)} 字节")
        
        # 生成DG11
        dg11_data = self.generate_dg11()
        dg11_path = os.path.join(self.output_dir, '010B.bin')
        with open(dg11_path, 'wb') as f:
            f.write(dg11_data)
        print(f"✅ DG11文件: {len(dg11_data)} 字节")
        
        # 生成DG12
        dg12_data = self.generate_dg12()
        dg12_path = os.path.join(self.output_dir, '010C.bin')
        with open(dg12_path, 'wb') as f:
            f.write(dg12_data)
        print(f"✅ DG12文件: {len(dg12_data)} 字节")
        
        # 生成DG15
        dg15_data = self.generate_dg15()
        dg15_path = os.path.join(self.output_dir, '010F.bin')
        with open(dg15_path, 'wb') as f:
            f.write(dg15_data)
        print(f"✅ DG15文件: {len(dg15_data)} 字节")
        
        # 生成SOD
        sod_data = self.generate_sod()
        sod_path = os.path.join(self.output_dir, '011D.bin')
        with open(sod_path, 'wb') as f:
            f.write(sod_data)
        print(f"✅ SOD文件: {len(sod_data)} 字节")
        
        print("\n=== 所有文件生成完成 ===")

if __name__ == "__main__":
    generator = PassportDataGenerator()
    generator.generate_all()