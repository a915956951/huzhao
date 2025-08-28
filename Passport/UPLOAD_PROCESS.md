# 护照数据正确上传流程说明

## 基于Java代码分析的关键发现

### 1. 状态管理

通过分析`PassportApplet.java`，发现了以下关键状态：

- **LOCKED (0x04)**: 小程序锁定状态
- **MUTUAL_AUTHENTICATED (0x02)**: BAC认证成功状态
- **HAS_MUTUALAUTHENTICATION_KEYS (0x01)**: 已设置BAC密钥状态
- **FILE_SELECTED (0x04)**: 文件已选择状态

### 2. 权限控制

```java
// processCreateFile - 创建文件
if (isLocked()) {
    ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
}

// processUpdateBinary - 写入数据
if (!hasFileSelected() || isLocked()) {
    ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
}

// processPutData - 设置密钥
if (isLocked()) {
    ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
}

// processSelectFile - 选择文件
if (isLocked() & !hasMutuallyAuthenticated()) {
    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
}

// processReadBinary - 读取文件
if (!hasMutuallyAuthenticated()) {
    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
}
```

### 3. MRZ数据处理（PUT_DATA with P2=0x62）

```java
// MRZ_TAG = 0x62
// 数据格式：文档号、出生日期、过期日期
buffer_p = BERTLVScanner.readTag(buffer, buffer_p); // 外层标签
buffer_p = BERTLVScanner.readLength(buffer, buffer_p);
// 解析三个内部TLV：docNr, dateOfBirth, dateOfExpiry
```

### 4. BAC认证流程

```java
// Step 1: GET_CHALLENGE (需要已设置BAC密钥)
if (!hasMutualAuthenticationKeys() || hasMutuallyAuthenticated()) {
    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
}

// Step 2: EXTERNAL_AUTHENTICATE (完成BAC)
if (!isChallenged() || hasMutuallyAuthenticated()) {
    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
}
// 成功后设置 MUTUAL_AUTHENTICATED 状态
```

## 正确的上传流程

### 初始化阶段（卡片未锁定时）

```
1. SELECT APPLET
   └─ 选择护照小程序

2. PUT_DATA (P1=0x00, P2=0x62)
   └─ 设置MRZ数据，初始化BAC密钥
   └─ 使用DG1中的文档号、出生日期、过期日期

3. CREATE_FILE + SELECT_FILE + UPDATE_BINARY
   └─ 创建并写入COM (0x011E)
   └─ 创建并写入DG1 (0x0101)
   └─ 创建并写入DG2 (0x0102)
   └─ 创建并写入DG11 (0x010B)
   └─ 创建并写入DG12 (0x010C)
   └─ 创建并写入DG15 (0x010F)
   └─ 创建并写入SOD (0x011D)

4. PUT_DATA (P1=0xDE, P2=0xAD) [可选]
   └─ 锁定小程序，防止后续修改
```

### 使用阶段（卡片锁定后）

```
1. SELECT APPLET
   └─ 选择护照小程序

2. GET_CHALLENGE
   └─ 获取8字节随机数RND.ICC

3. EXTERNAL_AUTHENTICATE
   └─ 完成BAC认证
   └─ 建立会话密钥

4. SELECT_FILE + READ_BINARY [使用安全消息]
   └─ 读取DG1、DG2等文件
   └─ 所有命令和响应都需要加密和MAC保护
```

## MRZ数据格式

从DG1提取的MRZ第二行（44字节）：
```
位置 0-8:   护照号（9位）
位置 9:     护照号校验位
位置 10-12: 国籍代码（3位）
位置 13-18: 出生日期YYMMDD（6位）
位置 19:    出生日期校验位
位置 20:    性别（1位）
位置 21-26: 过期日期YYMMDD（6位）
位置 27:    过期日期校验位
位置 28-41: 个人号码（14位，可选）
位置 42:    个人号码校验位
位置 43:    总校验位
```

## BAC密钥生成算法

```python
# 1. 构建密钥种子字符串
key_seed_str = doc_number + check1 + date_of_birth + check2 + date_of_expiry + check3

# 2. 计算SHA-1哈希
hash = SHA1(key_seed_str)
k_seed = hash[:16]  # 取前16字节

# 3. 生成Kenc
d_enc = k_seed || 0x00000001
k_enc = SHA1(d_enc)[:16]
k_enc = adjust_parity(k_enc)  # 调整DES奇偶校验位

# 4. 生成Kmac
d_mac = k_seed || 0x00000002
k_mac = SHA1(d_mac)[:16]
k_mac = adjust_parity(k_mac)
```

## 重要注意事项

1. **锁定状态的影响**
   - 一旦执行 `PUT_DATA(0xDE, 0xAD)` 锁定小程序，就无法再：
     - 创建新文件
     - 修改文件内容
     - 设置新的密钥
   - 锁定后只能通过BAC认证读取数据

2. **文件创建顺序**
   - 必须先 `CREATE_FILE` 创建文件并设置大小
   - 然后 `SELECT_FILE` 选择文件
   - 最后 `UPDATE_BINARY` 写入数据
   - 不能直接向不存在的文件写入数据

3. **BAC认证时机**
   - 初始化时不需要BAC认证
   - 锁定后必须通过BAC认证才能读取数据
   - BAC密钥必须在锁定前设置

4. **MRZ数据的重要性**
   - MRZ数据用于生成BAC密钥
   - 必须与DG1中存储的MRZ数据一致
   - 包括文档号、出生日期、过期日期及其校验位

## 测试步骤

1. **初始化测试**
   ```bash
   python upload_data_correct.py
   ```
   - 选择不锁定小程序
   - 验证所有文件创建成功

2. **BAC测试**
   - 重新运行脚本
   - 执行BAC认证测试
   - 验证能够通过认证

3. **锁定测试**
   - 再次运行脚本并选择锁定
   - 验证锁定后无法修改
   - 验证仍能通过BAC读取

## 常见问题

### Q: 为什么BAC认证失败？
A: 检查：
- MRZ数据是否正确设置（PUT_DATA 0x62）
- 文档号、日期格式是否正确
- 校验位计算是否准确

### Q: 为什么文件创建失败？
A: 检查：
- 小程序是否已锁定
- 文件ID是否正确
- 文件大小是否合理

### Q: 为什么无法读取文件？
A: 检查：
- 是否已完成BAC认证（锁定后）
- 文件是否已创建
- 文件是否已选择