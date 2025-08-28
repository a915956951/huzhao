# 护照智能卡数据生成和上传工具

这个工具集用于生成符合ICAO Doc 9303标准的护照数据并上传到智能卡中。

## 项目结构

```
Passport/
├── src/sos/passportapplet/     # Java智能卡小程序源代码
│   ├── PassportApplet.java     # 主要的护照小程序
│   ├── EvilPassportApplet.java # 扩展功能小程序
│   ├── FileSystem.java         # 文件系统管理
│   ├── PassportCrypto.java     # 加密功能
│   └── ...
├── old/                        # 原始bin文件样例
│   ├── 0101.bin               # DG1样例
│   ├── 0102.bin               # DG2样例
│   └── ...
├── generated_data/             # 生成的数据文件
├── 1.jpg                       # 护照照片（JPEG格式）
├── 1.jp2                       # 护照照片（JP2格式）
├── generate_passport_data.py   # 数据生成脚本
├── upload_data.py             # 数据上传脚本
├── analyze_bin.py             # 文件分析脚本
├── verify_generated.py        # 验证生成文件脚本
└── requirements.txt           # Python依赖
```

## 数据格式分析

通过对项目文件的详细分析，我们确认了以下关键信息：

### 文件标识符 (File IDs)
- **COM**: 0x011E - 公共数据元素
- **DG1**: 0x0101 - MRZ数据（机读区）
- **DG2**: 0x0102 - 生物特征数据（面部图像）
- **DG11**: 0x010B - 附加个人详情
- **DG12**: 0x010C - 附加文档详情
- **DG15**: 0x010F - 主动认证公钥
- **SOD**: 0x011D - 安全对象数据

### TLV标签
- **DG1**: 0x61
- **DG2**: 0x75
- **DG11**: 0x6B
- **DG12**: 0x6C
- **DG15**: 0x6F
- **SOD**: 0x77
- **COM**: 0x6E

### 重要发现：DG2图片格式
✅ **确认使用JPEG格式**，不是JP2格式
- 通过分析old/0102.bin文件，发现图片数据包含JPEG标识符（0xFF 0xD8）
- 生成的数据也使用JPEG格式以确保兼容性

### 签名和哈希算法
- **哈希算法**: SHA-256 (OID: 2.16.840.1.101.3.4.2.1)
- **签名算法**: RSA-SHA256 (符合PKCS#1)
- **密钥长度**: 2048位RSA密钥
- **数据结构**: PKCS#7 SignedData格式

## 安装和使用

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 生成护照数据

```bash
python generate_passport_data.py
```

这将生成以下文件在 `generated_data/` 目录中：
- `011E.bin` - COM文件
- `0101.bin` - DG1 (MRZ数据)
- `0102.bin` - DG2 (面部图像，JPEG格式)
- `010B.bin` - DG11 (附加个人详情)
- `010C.bin` - DG12 (附加文档详情)
- `010F.bin` - DG15 (主动认证公钥)
- `011D.bin` - SOD (安全对象数据)
- `aa_private_key.pem` - 主动认证私钥

### 3. 验证生成的数据

```bash
python verify_generated.py
```

### 4. 上传到智能卡

确保智能卡已插入读卡器，然后运行：

```bash
python upload_data.py
```

## 配置护照信息

在 `generate_passport_data.py` 中的 `passport_info` 字典里修改护照信息：

```python
self.passport_info = {
    'document_code': 'P<',
    'issuing_country': 'ARE',        # 发行国家
    'surname': 'SAMARA',             # 姓
    'given_names': 'NOUR',           # 名
    'passport_number': 'E5WX436483', # 护照号
    'nationality': 'ARE',            # 国籍
    'date_of_birth': '910825',       # 出生日期(YYMMDD)
    'sex': 'M',                      # 性别
    'date_of_expiry': '320629',      # 过期日期(YYMMDD)
    'personal_number': '',           # 个人号码
    'birth_place': 'DUBAI',          # 出生地
    'issue_date': '20220701'         # 签发日期(YYYYMMDD)
}
```

## 图片要求

- **格式**: JPEG（推荐）或JP2
- **尺寸**: 推荐200x240像素或更高
- **文件名**: 将图片命名为 `1.jpg` 并放在项目根目录

脚本会自动检测图片格式并转换为DG2所需的JPEG格式。

## 智能卡要求

- **卡类型**: JavaCard兼容的智能卡
- **小程序**: 需要预先安装护照小程序CAP文件
- **读卡器**: 支持PC/SC的智能卡读卡器

## 技术细节

### MRZ校验位计算
工具自动计算MRZ（机读区）的校验位，使用标准的权重算法：
- 权重: 7, 3, 1 (循环)
- 字母转数字: A=10, B=11, ..., Z=35
- '<' 字符 = 0

### TLV编码
所有数据使用标准的TLV (Tag-Length-Value) 编码：
- **短格式**: 长度 < 128
- **长格式**: 长度 >= 128，使用0x81或0x82前缀

### 加密和签名
- **BAC密钥**: 基于MRZ数据自动生成
- **主动认证**: 2048位RSA密钥对
- **SOD签名**: PKCS#7格式，SHA-256哈希

## 故障排除

### 常见问题

1. **"未找到读卡器"**
   - 确保读卡器已连接并安装驱动
   - 安装 `pip install pyscard`

2. **"未检测到智能卡"**
   - 确保智能卡正确插入
   - 检查卡片是否支持JavaCard

3. **"选择小程序失败"**
   - 确认护照小程序CAP文件已正确安装到卡上
   - 检查小程序AID是否正确

4. **"图片文件不存在"**
   - 确保项目根目录有 `1.jpg` 文件
   - 支持的格式：JPEG, JP2, PNG等

### 调试模式

在 `upload_data.py` 中启用详细的APDU日志来调试通信问题。

## 文件格式验证

生成的文件已通过以下验证：

✅ **TLV格式正确**: 所有文件使用标准TLV编码
✅ **标签匹配**: 与原始样例文件标签完全一致  
✅ **图片格式**: DG2使用JPEG格式（非JP2）
✅ **数据完整性**: 包含所有必需的数据组
✅ **哈希算法**: SOD使用SHA-256哈希
✅ **签名格式**: PKCS#7标准格式

## 许可证

基于SoS group的原始护照小程序实现，遵循GNU LGPL许可证。

## 贡献

欢迎提交问题报告和改进建议。

---

**⚠️ 重要提醒**: 此工具仅用于教育和研究目的。请确保遵守当地法律法规，不要用于非法用途。