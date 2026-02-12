"""HAR 转 JMeter JMX 转换脚本

功能概述：
- 将 Fiddler 导出的 HAR 文件转换为可直接运行的 JMeter JMX。
- 自动过滤静态资源请求，减少无效采样器。
- 从 JSON/JS/HTML/响应头/Set-Cookie 中提取动态参数并进行关联。
- 自动生成 Cookie 管理器、请求头管理器与基础响应断言。
- GET 与表单参数默认开启 URL Encode。

使用方法：
    C:/Python313/python.exe C:/Users/ww/Downloads/har_to_jmeter.py <har_file> [output_path_or_dir]

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

import base64
import json
import os
import re
import sys
from datetime import datetime
from urllib.parse import urlparse, unquote, urlencode, quote
from lxml import etree


class HarToJmxConverter:
    # Common static resource extensions to exclude
    EXCLUDE_EXTS = {
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".woff", ".woff2", ".ttf", ".ttc", ".eot", ".otf", ".svg",
        ".map", ".bmp", ".webp", ".mp4", ".mp3", ".avi", ".mov",
        ".m4a", ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar", ".tgz"
    }
    COOKIE_EXTRACT_KEYS = {
        "leid", "sessionid", "jsessionid", "sid", "uid",
        "token", "access_token", "refresh_token", "auth", "jwt"
    }
    HEADER_EXTRACT_KEYS = {
        "x-csrf-token", "x-xsrf-token", "x-auth-token",
        "authorization", "x-session-id"
    }
    HTML_KEY_HINTS = {
        "token", "csrf", "xsrf", "session", "sid", "auth", "nonce",
        "signature", "sign", "uid", "user", "guid", "jwt"
    }
    SUCCESS_MARKERS = [
        '"status": 200',
        '"status" : 200',
        '"code": 0',
        '"code" : 0',
        '"success": true',
        '"success" : true'
    ]
    VAR_PREFIX_STRIP = (
        "cookie_",
        "json_0__",
        "json_data_",
        "json_res_",
        "json_t_",
        "json_"
    )

    def __init__(self, har_path: str):
        self.har_path = har_path
        self.dynamic_params = []  # (value, var_name, source_idx, extractor_type, expr)
        self.value_to_var = {}    # {value: var_name}
        self.entries = []
        self.used_vars = set()
        self._parse_har()

    def _parse_har(self):
        with open(self.har_path, "r", encoding="utf-8-sig") as f:
            har_data = json.load(f)
        raw_entries = har_data.get("log", {}).get("entries", [])

        filtered_entries = []
        for entry in raw_entries:
            if not self._is_static_entry(entry):
                filtered_entries.append(entry)
        self.entries = filtered_entries

        print(
            f"HAR parsed: total={len(raw_entries)}, "
            f"filtered_static={len(raw_entries) - len(filtered_entries)}, "
            f"kept={len(filtered_entries)}"
        )

    def _is_static_entry(self, entry: dict) -> bool:
        req = entry.get("request", {})
        url = req.get("url", "") or ""
        parsed = urlparse(url)
        path = parsed.path or ""

        method = (req.get("method") or "").upper()
        if method == "OPTIONS":
            return True

        ext = ""
        if "." in path:
            _, _, ext = path.rpartition(".")
            ext = f".{ext.lower()}"
        if ext in self.EXCLUDE_EXTS:
            return True

        # Heuristic for common static directories
        static_dir_markers = ("/static/", "/assets/", "/img/", "/images/", "/fonts/", "/media/")
        if any(marker in path.lower() for marker in static_dir_markers) and method == "GET":
            return True

        mime = entry.get("response", {}).get("content", {}).get("mimeType", "").lower()
        if mime.startswith("image/"):
            return True
        if mime.startswith("audio/") or mime.startswith("video/"):
            return True
        if mime in (
            "text/css",
            "application/javascript", "text/javascript", "application/x-javascript",
            "font/woff", "font/woff2", "application/font-woff", "application/font-woff2",
            "application/vnd.ms-fontobject", "application/x-font-ttf",
            "application/pdf", "application/zip"
        ):
            return True

        return False

    def _is_dynamic_value(self, value: str) -> bool:
        if not isinstance(value, str) or value.strip() == "":
            return False

        val = value.strip()
        val_len = len(val)

        static_blacklist = {
            "true", "false", "null", "undefined", "none", "[]", "{}", "", " ",
            "admin", "user", "test", "demo", "prod", "dev", "qa", "local",
            "default", "unknown", "success", "fail", "error", "ok", "no", "yes",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
            "123", "1234", "654321", "123456", "000000", "111111"
        }
        if val.lower() in static_blacklist:
            return False

        has_alpha = bool(re.search(r"[a-zA-Z]", val))
        has_digit = bool(re.search(r"\d", val))
        has_special = bool(re.search(r"[-_:=~|;/.@#$%^&*()<>?]", val))
        has_cjk = bool(re.search(r"[\u4e00-\u9fff]", val))

        if val_len >= 10 and (has_alpha or has_cjk) and has_digit and has_special:
            return True
        if val_len >= 16 and val.isalnum():
            return True
        if val_len in (10, 13) and val.isdigit():
            return True
        if re.match(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            val
        ):
            return True
        if 4 <= val_len < 10 and val.isalnum() and val_len != 6:
            return True

        return False

    def _is_likely_json(self, text: str) -> bool:
        if not text or not isinstance(text, str):
            return False
        s = text.strip()
        return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))

    def _looks_like_json_value(self, text: str) -> bool:
        if not text or not isinstance(text, str):
            return False
        s = text.strip()
        return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))

    def _decode_response_text(self, content: dict) -> str:
        text = content.get("text", "")
        if not text:
            return ""
        encoding = (content.get("encoding") or "").lower()
        if encoding == "base64":
            try:
                raw = base64.b64decode(text)
                try:
                    return raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    return raw.decode("latin-1", errors="ignore")
            except Exception:
                return ""
        return text

    def _should_extract_key(self, key: str) -> bool:
        if not key:
            return False
        key_l = key.lower()
        return any(hint in key_l for hint in self.HTML_KEY_HINTS)

    def _normalize_var_name(self, name: str) -> str:
        if not name:
            return name
        for prefix in self.VAR_PREFIX_STRIP:
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        return name.lstrip("_") or name

    def _encode_query_value(self, value: str) -> tuple[str, str]:
        if not isinstance(value, str):
            return value, "true"
        if "${" in value:
            return value, "false"
        if self._looks_like_json_value(value):
            return quote(value, safe=""), "false"
        return value, "true"

    def _extract_dynamic_params(self):
        self.dynamic_params.clear()
        self.value_to_var.clear()

        for source_idx, entry in enumerate(self.entries):
            resp = entry.get("response", {})
            content = resp.get("content", {})
            text = self._decode_response_text(content)
            mime = content.get("mimeType", "").lower()

            if not text:
                continue

            if "json" in mime or "javascript" in mime:
                try:
                    text_clean = re.sub(r"^[\w$\.]+\((.*)\)\s*;?$", r"\1", text, flags=re.S)
                    json_data = json.loads(text_clean)
                    self._extract_from_json(json_data, source_idx)
                except Exception:
                    pass
            elif "html" in mime or mime.startswith("text/"):
                self._extract_from_html(text, source_idx)

            headers = resp.get("headers", [])
            for h in headers:
                name = h.get("name", "").strip().lower()
                value = h.get("value", "") or ""
                if not name:
                    continue

                if name in self.HEADER_EXTRACT_KEYS and value and self._is_dynamic_value(value):
                    if value not in self.value_to_var:
                        var_name = f"header_{name.replace('-', '_')}_{source_idx}"
                        var_name = self._normalize_var_name(var_name)
                        regex_expr = rf"(?i){re.escape(name)}:\s*([^\r\n]+)"
                        self.dynamic_params.append(
                            (value, var_name, source_idx, "header", regex_expr)
                        )
                        self.value_to_var[value] = var_name

                if "set-cookie" not in name:
                    continue

                for cookie_key in self.COOKIE_EXTRACT_KEYS:
                    m = re.search(rf"\b{re.escape(cookie_key)}=([^;\s]+)", value)
                    if not m:
                        continue
                    cookie_val = m.group(1).strip()
                    if cookie_val and self._is_dynamic_value(cookie_val):
                        if cookie_val not in self.value_to_var:
                            var_name = f"cookie_{cookie_key}_{source_idx}"
                            var_name = self._normalize_var_name(var_name)
                            regex_expr = rf"{re.escape(cookie_key)}=([^;]+)"
                            self.dynamic_params.append(
                                (cookie_val, var_name, source_idx, "cookie", regex_expr)
                            )
                            self.value_to_var[cookie_val] = var_name

    def _extract_from_html(self, text: str, source_idx: int):
        if not text:
            return

        hidden_input_re = re.compile(
            r"<input[^>]+type=[\"']?hidden[\"']?[^>]*>",
            flags=re.IGNORECASE
        )
        name_re = re.compile(r"\bname=[\"']([^\"']+)[\"']", flags=re.IGNORECASE)
        value_re = re.compile(r"\bvalue=[\"']([^\"']*)[\"']", flags=re.IGNORECASE)

        for tag in hidden_input_re.findall(text):
            name_m = name_re.search(tag)
            value_m = value_re.search(tag)
            if not name_m or not value_m:
                continue
            key = name_m.group(1)
            val = value_m.group(1)
            if self._should_extract_key(key) and self._is_dynamic_value(val):
                if val not in self.value_to_var:
                    var_name = f"html_{re.sub(r'[^\w]', '_', key).strip('_')}_{source_idx}"
                    var_name = self._normalize_var_name(var_name)
                    regex_expr = rf"name=[\"']{re.escape(key)}[\"'][^>]*value=[\"']([^\"']+)"
                    self.dynamic_params.append((val, var_name, source_idx, "regex", regex_expr))
                    self.value_to_var[val] = var_name

        meta_re = re.compile(r"<meta[^>]+>", flags=re.IGNORECASE)
        content_re = re.compile(r"\bcontent=[\"']([^\"']*)[\"']", flags=re.IGNORECASE)
        for tag in meta_re.findall(text):
            name_m = name_re.search(tag)
            content_m = content_re.search(tag)
            if not name_m or not content_m:
                continue
            key = name_m.group(1)
            val = content_m.group(1)
            if self._should_extract_key(key) and self._is_dynamic_value(val):
                if val not in self.value_to_var:
                    var_name = f"meta_{re.sub(r'[^\w]', '_', key).strip('_')}_{source_idx}"
                    var_name = self._normalize_var_name(var_name)
                    regex_expr = rf"name=[\"']{re.escape(key)}[\"'][^>]*content=[\"']([^\"']+)"
                    self.dynamic_params.append((val, var_name, source_idx, "regex", regex_expr))
                    self.value_to_var[val] = var_name

    def _extract_from_json(self, json_data, source_idx: int):
        def traverse(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if re.match(r"^[a-zA-Z0-9_]+$", k):
                        new_path = f"{path}.{k}" if path else k
                    else:
                        new_path = f"{path}['{k}']" if path else f"['{k}']"
                    traverse(v, new_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    traverse(item, f"{path}[{i}]")
            else:
                val_str = str(obj).strip()
                if self._is_dynamic_value(val_str):
                    safe_path = re.sub(r"[^\w]", "_", path).strip("_")
                    var_name = f"json_{safe_path}_{source_idx}"
                    var_name = self._normalize_var_name(var_name)
                    if val_str not in self.value_to_var:
                        json_path = f"$.{path}"
                        self.dynamic_params.append((val_str, var_name, source_idx, "json", json_path))
                        self.value_to_var[val_str] = var_name
        traverse(json_data)

    def _replace_dynamic_values(self, content: str, current_idx: int) -> str:
        if not content:
            return content

        sorted_params = sorted(self.dynamic_params, key=lambda x: len(x[0]), reverse=True)
        for value, var_name, source_idx, *_ in sorted_params:
            if source_idx < current_idx and value in content:
                content = content.replace(value, f"${{{var_name}}}")
                self.used_vars.add(var_name)
        return content

    def _replace_dynamic_in_json_text(self, text: str, current_idx: int) -> str:
        if not text:
            return text
        try:
            obj = json.loads(text)
        except Exception:
            return text

        allowed_map = {}
        for value, var_name, source_idx, *_ in self.dynamic_params:
            if source_idx < current_idx and isinstance(value, str) and value:
                if value not in allowed_map:
                    allowed_map[value] = var_name

        def replace_in_value(val: str) -> str:
            var = allowed_map.get(val)
            if var:
                self.used_vars.add(var)
                return f"${{{var}}}"
            return val

        def walk(node):
            if isinstance(node, dict):
                return {k: walk(v) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(item) for item in node]
            if isinstance(node, str):
                return replace_in_value(node)
            return node

        new_obj = walk(obj)
        try:
            return json.dumps(new_obj, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return text

    def _scan_used_variables(self):
        self.used_vars.clear()
        for idx, entry in enumerate(self.entries):
            req = entry.get("request", {})
            method = (req.get("method") or "GET").upper()
            full_url = req.get("url", "")
            parsed = urlparse(full_url)
            original_path = parsed.path or "/"
            query_string = req.get("queryString", [])

            path_to_check = original_path
            if method == "POST":
                path_to_check = self._build_full_path(original_path, query_string, method)
            _ = self._replace_dynamic_values(path_to_check, idx)

            for item in query_string:
                v = item.get("value", "")
                if v:
                    _ = self._replace_dynamic_values(v, idx)

            for h in req.get("headers", []):
                name = h.get("name", "").strip().lower()
                if name:
                    val = h.get("value", "")
                    if val:
                        _ = self._replace_dynamic_values(val, idx)

            post_data = req.get("postData", {})
            if method == "POST" and post_data:
                mime_type = post_data.get("mimeType", "").lower()
                post_text = post_data.get("text", "")
                post_params = post_data.get("params", [])

                if self._is_likely_json(post_text):
                    _ = self._replace_dynamic_in_json_text(post_text, idx)
                elif "x-www-form-urlencoded" in mime_type:
                    if post_params:
                        for p in post_params:
                            v = p.get("value", "")
                            if v:
                                _ = self._replace_dynamic_values(v, idx)
                    elif post_text:
                        for k, v in self._parse_form_text(post_text):
                            if v:
                                _ = self._replace_dynamic_values(v, idx)
                elif post_text:
                    _ = self._replace_dynamic_values(post_text, idx)

    def _parse_form_text(self, text: str) -> list:
        params = []
        if not text:
            return params
        for param in text.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                k = unquote(k.strip())
                v = unquote(v.strip())
                params.append((k, v))
            elif param.strip():
                k = unquote(param.strip())
                params.append((k, ""))
        return params

    def _build_full_path(self, path: str, query_string: list, method: str) -> str:
        if method != "POST" or not query_string:
            return path

        query_params = {}
        for item in query_string:
            k = (item.get("name") or "").strip()
            v = (item.get("value") or "").strip()
            if k:
                query_params[k] = v

        pairs = []
        for k, v in query_params.items():
            enc_val, _ = self._encode_query_value(v)
            pairs.append(f"{quote(k, safe='') if k else k}={enc_val}")
        query_str = "&".join(pairs)
        if "?" in path:
            return f"{path}&{query_str}"
        return f"{path}?{query_str}"

    def _add_query_params_to_arguments(self, sampler: etree.Element, query_string: list, current_idx: int):
        args = etree.SubElement(sampler, "elementProp", name="HTTPsampler.Arguments", elementType="Arguments")
        args_coll = etree.SubElement(args, "collectionProp", name="Arguments.arguments")

        for item in query_string:
            k = (item.get("name") or "").strip()
            v = (item.get("value") or "").strip()
            if k:
                replaced = self._replace_dynamic_values(v, current_idx)
                replaced, _ = self._encode_query_value(replaced)
                arg = etree.SubElement(args_coll, "elementProp", name=k, elementType="HTTPArgument")
                etree.SubElement(arg, "boolProp", name="HTTPArgument.always_encode").text = "true"
                etree.SubElement(arg, "boolProp", name="HTTPArgument.use_equals").text = "true"
                etree.SubElement(arg, "stringProp", name="Argument.name").text = k
                etree.SubElement(arg, "stringProp", name="Argument.value").text = replaced
                etree.SubElement(arg, "stringProp", name="Argument.metadata").text = "="

    def _create_http_sampler(self, entry: dict, idx: int) -> etree.Element:
        req = entry["request"]
        method = req["method"].upper()
        full_url = req["url"]
        parsed = urlparse(full_url)
        domain = parsed.hostname or ""
        protocol = parsed.scheme or "http"
        port = parsed.port or (443 if protocol == "https" else 80)
        original_path = parsed.path or "/"
        query_string = req.get("queryString", [])

        full_path = self._build_full_path(original_path, query_string, method)
        path_for_sampler = full_path if method == "POST" else original_path
        replaced_path = self._replace_dynamic_values(path_for_sampler, idx)

        testname = f"Step {idx + 1}: {method} {full_url}"
        sampler = etree.Element(
            "HTTPSamplerProxy",
            guiclass="HttpTestSampleGui",
            testclass="HTTPSamplerProxy",
            testname=testname,
            enabled="true"
        )

        etree.SubElement(sampler, "stringProp", name="HTTPSampler.domain").text = domain
        etree.SubElement(sampler, "stringProp", name="HTTPSampler.port").text = str(port)
        etree.SubElement(sampler, "stringProp", name="HTTPSampler.protocol").text = protocol
        etree.SubElement(sampler, "stringProp", name="HTTPSampler.path").text = replaced_path
        etree.SubElement(sampler, "stringProp", name="HTTPSampler.method").text = method
        etree.SubElement(sampler, "stringProp", name="HTTPSampler.contentEncoding").text = "UTF-8"
        etree.SubElement(sampler, "boolProp", name="HTTPSampler.follow_redirects").text = "true"
        etree.SubElement(sampler, "boolProp", name="HTTPSampler.use_keepalive").text = "true"

        if method == "GET" and query_string:
            self._add_query_params_to_arguments(sampler, query_string, idx)

        post_data = req.get("postData", {})
        if post_data and method == "POST":
            mime_type = post_data.get("mimeType", "").lower()
            post_text = post_data.get("text", "")
            post_params = post_data.get("params", [])

            if self._is_likely_json(post_text):
                raw_body = self._replace_dynamic_in_json_text(post_text, idx)
                etree.SubElement(sampler, "boolProp", name="HTTPSampler.postBodyRaw").text = "true"
                req_body = etree.SubElement(sampler, "elementProp", name="HTTPsampler.Arguments", elementType="Arguments")
                req_body_coll = etree.SubElement(req_body, "collectionProp", name="Arguments.arguments")
                body_arg = etree.SubElement(req_body_coll, "elementProp", name="", elementType="HTTPArgument")
                etree.SubElement(body_arg, "boolProp", name="HTTPArgument.always_encode").text = "false"
                etree.SubElement(body_arg, "boolProp", name="HTTPArgument.use_equals").text = "false"
                etree.SubElement(body_arg, "stringProp", name="Argument.value").text = raw_body
                etree.SubElement(body_arg, "stringProp", name="Argument.metadata").text = "="
                etree.SubElement(sampler, "stringProp", name="HTTPSampler.contentType").text = "application/json; charset=UTF-8"

            elif "x-www-form-urlencoded" in mime_type:
                etree.SubElement(sampler, "boolProp", name="HTTPSampler.postBodyRaw").text = "false"
                args = etree.SubElement(sampler, "elementProp", name="HTTPsampler.Arguments", elementType="Arguments")
                args_coll = etree.SubElement(args, "collectionProp", name="Arguments.arguments")

                if post_params:
                    for param in post_params:
                        k = param.get("name", "").strip()
                        v = param.get("value", "").strip()
                        if k:
                            replaced = self._replace_dynamic_values(v, idx)
                            arg = etree.SubElement(args_coll, "elementProp", name=k, elementType="HTTPArgument")
                            etree.SubElement(arg, "boolProp", name="HTTPArgument.always_encode").text = "true"
                            etree.SubElement(arg, "boolProp", name="HTTPArgument.use_equals").text = "true"
                            etree.SubElement(arg, "stringProp", name="Argument.name").text = k
                            etree.SubElement(arg, "stringProp", name="Argument.value").text = replaced
                            etree.SubElement(arg, "stringProp", name="Argument.metadata").text = "="
                elif post_text:
                    form_params = self._parse_form_text(post_text)
                    for k, v in form_params:
                        if k:
                            replaced = self._replace_dynamic_values(v, idx)
                            arg = etree.SubElement(args_coll, "elementProp", name=k, elementType="HTTPArgument")
                            etree.SubElement(arg, "boolProp", name="HTTPArgument.always_encode").text = "true"
                            etree.SubElement(arg, "boolProp", name="HTTPArgument.use_equals").text = "true"
                            etree.SubElement(arg, "stringProp", name="Argument.name").text = k
                            etree.SubElement(arg, "stringProp", name="Argument.value").text = replaced
                            etree.SubElement(arg, "stringProp", name="Argument.metadata").text = "="
                etree.SubElement(sampler, "stringProp", name="HTTPSampler.contentType").text = "application/x-www-form-urlencoded; charset=UTF-8"

            elif post_text:
                raw_body = self._replace_dynamic_values(post_text, idx)
                etree.SubElement(sampler, "boolProp", name="HTTPSampler.postBodyRaw").text = "true"
                req_body = etree.SubElement(sampler, "elementProp", name="HTTPsampler.Arguments", elementType="Arguments")
                req_body_coll = etree.SubElement(req_body, "collectionProp", name="Arguments.arguments")
                body_arg = etree.SubElement(req_body_coll, "elementProp", name="", elementType="HTTPArgument")
                etree.SubElement(body_arg, "boolProp", name="HTTPArgument.always_encode").text = "false"
                etree.SubElement(body_arg, "boolProp", name="HTTPArgument.use_equals").text = "false"
                etree.SubElement(body_arg, "stringProp", name="Argument.value").text = raw_body
                etree.SubElement(body_arg, "stringProp", name="Argument.metadata").text = "="
                if mime_type and mime_type != "application/octet-stream":
                    etree.SubElement(sampler, "stringProp", name="HTTPSampler.contentType").text = mime_type
                else:
                    etree.SubElement(sampler, "stringProp", name="HTTPSampler.contentType").text = "text/plain; charset=UTF-8"

        if not (method == "GET" and query_string) and not (method == "POST" and post_data):
            args = etree.SubElement(sampler, "elementProp", name="HTTPsampler.Arguments", elementType="Arguments")
            etree.SubElement(args, "collectionProp", name="Arguments.arguments")

        return sampler

    def _create_extractor(self, var_name: str, extractor_type: str, expr: str) -> etree.Element:
        if extractor_type == "json":
            extractor = etree.Element(
                "JSONPostProcessor",
                guiclass="JSONPostProcessorGui",
                testclass="JSONPostProcessor",
                testname=f"Extract {var_name}",
                enabled="true"
            )
            etree.SubElement(extractor, "stringProp", name="JSONPostProcessor.referenceNames").text = var_name
            etree.SubElement(extractor, "stringProp", name="JSONPostProcessor.jsonPathExprs").text = expr
            etree.SubElement(extractor, "stringProp", name="JSONPostProcessor.match_numbers").text = "1"
            etree.SubElement(extractor, "stringProp", name="JSONPostProcessor.defaultValues").text = f"{var_name}_EXTRACT_FAIL"
            return extractor

        if extractor_type == "cookie":
            extractor = etree.Element(
                "RegexExtractor",
                guiclass="RegexExtractorGui",
                testclass="RegexExtractor",
                testname=f"Extract {var_name} (cookie)",
                enabled="true"
            )
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useHeaders").text = "true"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useBody").text = "false"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useBodyAsDocument").text = "false"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useUrl").text = "false"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useCode").text = "false"

            etree.SubElement(extractor, "stringProp", name="RegexExtractor.refname").text = var_name
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.regex").text = expr
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.template").text = "$1"
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.default").text = ""
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.default_empty_value").text = "true"
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.match_number").text = "1"
            return extractor

        if extractor_type == "header":
            extractor = etree.Element(
                "RegexExtractor",
                guiclass="RegexExtractorGui",
                testclass="RegexExtractor",
                testname=f"Extract {var_name} (header)",
                enabled="true"
            )
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useHeaders").text = "true"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useBody").text = "false"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useBodyAsDocument").text = "false"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useUrl").text = "false"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useCode").text = "false"

            etree.SubElement(extractor, "stringProp", name="RegexExtractor.refname").text = var_name
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.regex").text = expr
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.template").text = "$1"
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.default").text = ""
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.default_empty_value").text = "true"
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.match_number").text = "1"
            return extractor

        if extractor_type == "regex":
            extractor = etree.Element(
                "RegexExtractor",
                guiclass="RegexExtractorGui",
                testclass="RegexExtractor",
                testname=f"Extract {var_name} (regex)",
                enabled="true"
            )
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useHeaders").text = "false"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useBody").text = "true"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useBodyAsDocument").text = "false"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useUrl").text = "false"
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.useCode").text = "false"

            etree.SubElement(extractor, "stringProp", name="RegexExtractor.refname").text = var_name
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.regex").text = expr
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.template").text = "$1"
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.default").text = ""
            etree.SubElement(extractor, "boolProp", name="RegexExtractor.default_empty_value").text = "true"
            etree.SubElement(extractor, "stringProp", name="RegexExtractor.match_number").text = "1"
            return extractor

        return etree.Element("hashTree")

    def _create_assertions(self) -> list:
        response_assert = etree.Element(
            "ResponseAssertion",
            guiclass="AssertionGui",
            testclass="ResponseAssertion",
            testname="Assert Response Success",
            enabled="true"
        )
        etree.SubElement(response_assert, "boolProp", name="Assertion.assume_success").text = "false"
        etree.SubElement(response_assert, "stringProp", name="Assertion.test_field").text = "Assertion.response_data"
        etree.SubElement(response_assert, "intProp", name="Assertion.test_type").text = "0"
        etree.SubElement(response_assert, "boolProp", name="Assertion.OR").text = "true"
        test_coll = etree.SubElement(response_assert, "collectionProp", name="Assertion.test_strings")
        for marker in self.SUCCESS_MARKERS:
            etree.SubElement(test_coll, "stringProp", name="").text = marker

        return [response_assert]

    def convert(self, output_path: str = None):
        self._extract_dynamic_params()
        print(f"Dynamic params extracted: {len(self.dynamic_params)}")
        self._scan_used_variables()
        print(f"Dynamic params actually used: {len(self.used_vars)}")

        root = etree.Element("jmeterTestPlan", version="1.2", properties="5.0", jmeter="5.4.3")
        root_ht = etree.SubElement(root, "hashTree")

        test_plan = etree.SubElement(
            root_ht, "TestPlan",
            guiclass="TestPlanGui",
            testclass="TestPlan",
            testname="HAR Conversion Test Plan",
            enabled="true"
        )
        etree.SubElement(test_plan, "boolProp", name="TestPlan.functional_mode").text = "false"
        etree.SubElement(test_plan, "stringProp", name="TestPlan.comments").text = "Auto-generated from HAR"
        user_vars = etree.SubElement(
            test_plan, "elementProp",
            name="TestPlan.user_defined_variables",
            elementType="Arguments",
            guiclass="ArgumentsPanel",
            testclass="Arguments",
            enabled="true"
        )
        etree.SubElement(user_vars, "collectionProp", name="Arguments.arguments")
        test_plan_ht = etree.SubElement(root_ht, "hashTree")

        cookie_manager = etree.SubElement(
            test_plan_ht, "CookieManager",
            guiclass="CookiePanel",
            testclass="CookieManager",
            testname="HTTP Cookie Manager",
            enabled="true"
        )
        etree.SubElement(cookie_manager, "boolProp", name="CookieManager.clearEachIteration").text = "false"
        etree.SubElement(test_plan_ht, "hashTree")

        thread_group = etree.SubElement(
            test_plan_ht, "ThreadGroup",
            guiclass="ThreadGroupGui",
            testclass="ThreadGroup",
            testname="Main Thread Group",
            enabled="true"
        )
        etree.SubElement(thread_group, "stringProp", name="ThreadGroup.num_threads").text = "1"
        etree.SubElement(thread_group, "stringProp", name="ThreadGroup.ramp_time").text = "1"
        etree.SubElement(thread_group, "stringProp", name="ThreadGroup.on_sample_error").text = "continue"
        etree.SubElement(thread_group, "elementProp", name="ThreadGroup.main_controller", elementType="LoopController")
        loop_ctrl = etree.SubElement(thread_group, "elementProp", name="LoopController", elementType="LoopController")
        etree.SubElement(loop_ctrl, "boolProp", name="LoopController.continue_forever").text = "false"
        etree.SubElement(loop_ctrl, "stringProp", name="LoopController.loops").text = "1"
        thread_group_ht = etree.SubElement(test_plan_ht, "hashTree")

        for idx, entry in enumerate(self.entries):
            sampler = self._create_http_sampler(entry, idx)
            thread_group_ht.append(sampler)
            sampler_ht = etree.SubElement(thread_group_ht, "hashTree")

            headers = entry["request"].get("headers", [])
            if headers:
                header_manager = etree.SubElement(
                    sampler_ht, "HeaderManager",
                    guiclass="HeaderPanel",
                    testclass="HeaderManager",
                    testname="HTTP Header Manager",
                    enabled="true"
                )
                header_coll = etree.SubElement(header_manager, "collectionProp", name="HeaderManager.headers")
                for h in headers:
                    name = h.get("name", "").strip()
                    value = h.get("value", "").strip()
                    if name:
                        replaced_value = self._replace_dynamic_values(value, idx)
                        header_elem = etree.SubElement(header_coll, "elementProp", name="", elementType="Header")
                        etree.SubElement(header_elem, "stringProp", name="Header.name").text = name
                        etree.SubElement(header_elem, "stringProp", name="Header.value").text = replaced_value
                etree.SubElement(sampler_ht, "hashTree")

            for value, var_name, source_idx, extractor_type, expr in self.dynamic_params:
                if source_idx == idx and var_name in self.used_vars:
                    extractor = self._create_extractor(var_name, extractor_type, expr)
                    sampler_ht.append(extractor)
                    etree.SubElement(sampler_ht, "hashTree")

            for assertion in self._create_assertions():
                sampler_ht.append(assertion)
                etree.SubElement(sampler_ht, "hashTree")

        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_path = f"har_converted_{timestamp}.jmx"
        else:
            if os.path.isdir(output_path):
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                output_path = os.path.join(output_path, f"har_converted_{timestamp}.jmx")
            out_dir = os.path.dirname(output_path) or "."
            os.makedirs(out_dir, exist_ok=True)

        etree.indent(root, space="  ")
        with open(output_path, "wb") as f:
            f.write(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
            f.write(etree.tostring(root, encoding="utf-8", pretty_print=True))

        print(f"JMX generated: {output_path}")
        print(f"Requests included: {len(self.entries)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python har_to_jmeter_v2.py <har_file_path> [output_jmx_path]")
        sys.exit(1)
    har_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) >= 3 else None
    converter = HarToJmxConverter(har_path)
    converter.convert(output_path)
