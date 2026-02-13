# Fiddler-To-Jmx
将Fiddler导出的Har文件，通过该脚本转换为Jmeter可执行的Jmx脚本
"""HAR 转 JMeter JMX 转换脚本

功能概述：
- 将 Fiddler 导出的 HAR 文件转换为可直接运行的 JMeter JMX。
- Fiddler - File / Export Session / 全选/选中部分请求 / HTTPArchive v1.1 / v1.2 
- 自动过滤静态资源请求，减少无效采样器。
- 从 JSON/JS/HTML/响应头/Set-Cookie 中提取动态参数并进行关联。
- 自动生成 Cookie 管理器、请求头管理器与基础响应断言。
- GET 与表单参数默认开启 URL Encode。

使用方法：
- 安装python3+，未配置全局python环境变量使用全路径：
    C:/Python313/python.exe C:/Users/www/Downloads/har_to_jmeter.py <har_file> [output_path_or_dir]
- 配置了python全局变量时：
    python /har_to_jmeter.py <har_file> [output_path_or_dir]  

输出说明：
- 未指定输出路径时，自动生成 har_converted_YYYYMMDDHHMMSS.jmx。
- 输出路径为目录时，自动在该目录下生成文件。

注意事项：
- JSON 请求体以 raw body 方式写入，不做 URL Encode。
- 动态参数仅在后续请求中被引用时才会生成对应提取器。
- 如需扩展动态参数提取规则，可调整 COOKIE_EXTRACT_KEYS/HEADER_EXTRACT_KEYS/HTML_KEY_HINTS。
- 正则表达式提取器的模版字符串有漏洞需转换之后检查。
- 在线程组下请求的最后添加 View Results Tree、Debug Sampler，查看 View Results Tree 中 Debug Sampler 的响应值中所有变量及关联的动态值是否正确提取。
- 正则、边界等处理器中的 Default Value 必须勾选 Use empty value，否则提取失败时会使用默认值，导致后续请求无法正确关联动态参数。
"""
