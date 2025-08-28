#!/usr/bin/env python3
"""
检查SOD文件的签名信息
"""
from asn1crypto import cms as asn1_cms
import os

def check_sod_signature():
    sod_path = 'generated_data/011D.bin'
    with open(sod_path, 'rb') as f:
        sod_data = f.read()
    
    # 跳过外层TLV
    pkcs7_data = sod_data[4:]
    
    try:
        content_info = asn1_cms.ContentInfo.load(pkcs7_data)
        signed_data = content_info['content']
        
        print('=== SOD签名信息 ===')
        print(f'PKCS#7版本: {signed_data["version"]}')
        
        # 签名者信息
        signer_infos = signed_data['signer_infos']
        for i, signer_info in enumerate(signer_infos):
            print(f'\n签名者 {i+1}:')
            print(f'  版本: {signer_info["version"]}')
            print(f'  摘要算法: {signer_info["digest_algorithm"]["algorithm"]}')
            print(f'  签名算法: {signer_info["signature_algorithm"]["algorithm"]}')
            
            # 发行者和序列号
            sid = signer_info['sid']
            try:
                if hasattr(sid, 'chosen') and sid.chosen:
                    issuer_serial = sid.chosen
                    print(f'  发行者: {issuer_serial["issuer"]}')
                    print(f'  序列号: {issuer_serial["serial_number"]}')
            except Exception as e:
                print(f'  签名者ID解析错误: {e}')
        
        # 证书信息
        certificates = signed_data['certificates'] if 'certificates' in signed_data else []
        print(f'\n包含的证书数量: {len(certificates)}')
        
        for i, cert_choice in enumerate(certificates):
            if 'certificate' in cert_choice:
                cert = cert_choice['certificate']
                print(f'证书 {i+1}: {cert["tbs_certificate"]["subject"]}')
                print(f'证书算法: {cert["signature_algorithm"]["algorithm"]}')
        
    except Exception as e:
        print(f'解析错误: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_sod_signature()