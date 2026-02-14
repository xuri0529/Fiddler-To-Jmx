"""HAR 转 JMeter JMX 转换脚本

功能描述：
- 该脚本将 Fiddler 导出的 HAR 转换成可直接运行的 JMeter JMX，生成一个完整的 Test Plan、Thread Group、HTTP Sampler、Header Manager、Cookie Manager、断言与结果查看器。
- 会读取 HAR 中的 log.entries，过滤静态资源请求（按扩展名、常见静态目录、响应 MIME 类型、OPTIONS 方法等规则）以减少无效采样器。
- 自动识别并关联动态参数：从 JSON/JavaScript/HTML 响应体、响应头与 Set-Cookie 中提取候选动态值；只在后续请求真正引用时才创建对应的提取器，避免无用关联。
- 请求构造规则：
    - GET 请求：路径使用原始 path，查询参数写入 HTTPsampler.Arguments，并开启 HTTPArgument.always_encode。
    - POST 请求：
        - JSON Body：识别为 JSON 时用 raw body 写入，并将 JSON 内可替换字段替换为变量；postBodyRaw=true，contentType=application/json; charset=UTF-8。
        - application/x-www-form-urlencoded：按参数写入并默认 URL Encode。
        - 其他文本/二进制：按 raw body 写入，若 MIME 不明确则使用 text/plain; charset=UTF-8。
- 自动生成基础响应断言：包含多个成功标识（如 "status": 200、"code": 0、"success": true）。
- 自动生成调试与结果查看器：在采样器后追加 DebugSampler 与 View Results Tree 便于验证关联变量。

使用方法：
- 依赖：
    - Python 3.x
    - lxml
- 命令行用法：
    - 未配置 Python 环境变量时：
        C:/Python313/python.exe C:/Users/xxx/Downloads/har_to_jmx.py <har_file> [output_path_or_dir]
    - 已配置 Python 环境变量时：
        python har_to_jmx.py <har_file> [output_path_or_dir]
- 参数说明：
    - <har_file>：必填，HAR 文件路径。
    - [output_path_or_dir]：可选，输出文件路径或输出目录。

输出说明：
- 未指定输出路径时：生成 har_converted_YYYYMMDDHHMMSS.jmx，输出到当前目录。
- 指定输出路径为目录时：在该目录下生成 har_converted_YYYYMMDDHHMMSS.jmx。
- 指定输出路径为文件时：直接写入该文件，并自动创建目录（若不存在）。
- 运行时控制台会打印：
    - HAR 解析统计：总请求数、过滤静态请求数、保留请求数。
    - 动态参数统计：提取数量、实际被引用数量。
    - 最终生成的 JMX 路径与包含的请求数。

注意事项：
- JSON 请求体以 raw body 方式写入，不做 URL Encode。
- 动态参数仅在后续请求中被引用时才会生成对应提取器。
- 如需扩展动态参数提取规则，可调整 COOKIE_EXTRACT_KEYS/HEADER_EXTRACT_KEYS/HTML_KEY_HINTS。
- 正则表达式提取器的模版字符串有漏洞需转换之后检查。
- 在线程组下请求的最后添加 View Results Tree、Debug Sampler，查看 View Results Tree 中 Debug Sampler 的响应值中所有变量及关联的动态值是否正确提取。
- 正则、边界等处理器中的 Default Value 必须勾选 Use empty value，否则提取失败时会使用默认值，导致后续请求无法正确关联动态参数。
"""
