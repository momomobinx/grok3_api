# **快速使用指南**  

## **1. 配置 Cookie**  
- **📂 存放位置：** 将你的 Cookie 以 `.txt` 格式存放在 `cookies` 文件夹中。  
- **📌 命名规则：** 每个 `.txt` 文件代表一条 Cookie，文件名可自由命名。  
- **⚠️ 内容要求：** 仅保留 `sso=xxxxxx` 字段，删除其他内容。  

## **2. 启动项目**
- **✏️ 写入Token：** 修改`启动.bat`中的`Token`字段。默认为：123456
- **▶ 运行** `启动.bat` **一键启动**。  

## **3. 解决授权错误**  
如果遇到 **❌ "Unauthorized: Bearer token required"** 错误，请尝试在 **酒馆 API** 的 **自定义密钥** 中输入默认 Token：123456（或者你自己设定的Token）
## **4. 出现\n\n格式问题**  
请用[正则](https://github.com/orzogc/grok3_api) 作者：[orzogc](https://github.com/orzogc)
---

### **附加事项**  
✅ **新增功能：**  
- 通过 `-cookiesDir` 参数自定义 `cookies` 目录位置。
- 增加`DualStack: false`字段，强制使用IPV4。（位于代码681行处，可自行选择是否使用，默认隐藏字段） 
- 3月8日：增加"搜索"功能，需在参数中，手动写入代码`enableSearch: 1`开启。
- 增加`-longtxt`启动项进行附件上传

❌ **不支持的文件格式：**  
- **不支持** `xxxx.xxx.txt` 形式的文件名。  
- **请直接使用** `xxxxx.txt` 格式。  

📌 **其他说明**  
- 其余功能与原项目相同，参考：[grok3_api](https://github.com/orzogc/grok3_api)

**安卓用户提示**
- 启动命令参考（后台启动） `./grok-server -token your-auth-token -cookie xxxxxxx -port 8180 &`
- 已用`DualStack: false`强制使用IPV4。
- 具体使用参考：https://grok.com/share/bGVnYWN5_7cafcf60-ca6b-4097-bdbc-ffaee19b2e2c
