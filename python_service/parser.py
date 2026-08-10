import re
import esprima
from typing import List, Dict, Any, Set, Optional
from pydantic import BaseModel

class ExtractedEndpoint(BaseModel):
    method: str
    path: str
    source_url: str = ""
    parameters: List[str] = []
    headers: List[str] = []
    request_body: Dict[str, Any] = {}
    auth_mechanisms: List[str] = []
    raw_snippet: str = ""
    category: str = "REST"  # REST, UI Route, Angular Route, GraphQL, WebSocket, SignalR
    is_bola_candidate: bool = False

class ExtractedSecret(BaseModel):
    secret_type: str
    key_name: str
    value: str
    source_url: str = ""

class ExtractedFlag(BaseModel):
    flag_type: str
    name: str
    snippet: str
    source_url: str = ""

class ParseResult(BaseModel):
    endpoints: List[ExtractedEndpoint]
    secrets: List[ExtractedSecret]
    flags: List[ExtractedFlag]

class JSParser:
    def __init__(self):
        self.verbs = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
        
        # False Positive Exclusion Sets
        self.ignored_namespaces = {
            "w3.org", "schemas.xmlsoap.org", "schema.org", "schemas.microsoft.com",
            "ns.adobe.com", "purl.org", "github.com", "apache.org", "facebook.com",
            "google.com", "googleapis.com", "gstatic.com", "twitter.com", "schema.management"
        }
        
        self.ignored_extensions = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".map", ".scss", ".less"
        )
        
        self.reserved_keywords = {
            "of", "in", "for", "the", "and", "or", "not", "is", "it", "to", "a", "an",
            "if", "else", "function", "return", "var", "let", "const", "true", "false",
            "null", "undefined", "object", "string", "number", "boolean", "array", "data"
        }

        # Secret discovery patterns
        self.secret_patterns = [
            ("API Key", r'(?i)(?:api_?key|apikey|secret_?key|client_?secret|access_?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,64})["\']'),
            ("AWS Key", r'(?i)(AKIA[0-9A-Z]{16})'),
            ("Firebase URL", r'https://[a-z0-9\-]+\.firebaseio\.com'),
            ("Stripe Key", r'pk_(?:live|test)_[0-9a-zA-Z]{24,99}'),
            ("JWT Storage", r'(?:localStorage|sessionStorage)\.setItem\(["\']([a-zA-Z0-9_\-]+(?:token|jwt|auth)[a-zA-Z0-9_\-]*)["\']'),
            ("Internal Host", r'["\'](http://(?:127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|localhost)[^\s"\'\`]*)["\']')
        ]
        
        # Feature flag patterns
        self.flag_patterns = [
            ("Role Guard", r'(?i)(?:isAdmin|is_admin|hasRole|hasPermission|user\.role|permissions\.includes)\s*\([^)]*\)'),
            ("Permission String", r'["\']([A-Z0-9_]{3,30}_(?:READ|WRITE|DELETE|MANAGE|CREATE|UPDATE|ADMIN))["\']'),
            ("Feature Toggle", r'(?i)(?:feature_?flags?|enable_[a-zA-Z0-9_]+|is_?enabled)\s*[:=]\s*(?:true|false)')
        ]

    def parse_code(self, code: str, source_url: str = "") -> ParseResult:
        endpoints: List[ExtractedEndpoint] = []
        seen_ep: Set[str] = set()

        # Phase 1: AST Parsing
        try:
            tree = esprima.parseScript(code, tolerant=True, loc=False)
            ast_endpoints = self._walk_ast(tree, source_url)
            for ep in ast_endpoints:
                if self._is_valid_endpoint(ep):
                    key = f"{ep.method}:{ep.path}"
                    if key not in seen_ep:
                        seen_ep.add(key)
                        endpoints.append(ep)
        except Exception:
            pass

        # Phase 2: Router & Route Fallback
        router_endpoints = self._extract_router_definitions(code, source_url)
        for ep in router_endpoints:
            if self._is_valid_endpoint(ep):
                key = f"{ep.method}:{ep.path}"
                if key not in seen_ep:
                    seen_ep.add(key)
                    endpoints.append(ep)

        # Phase 3: Regex Fallback for REST & GraphQL
        regex_endpoints = self._regex_fallback(code, source_url)
        for ep in regex_endpoints:
            if self._is_valid_endpoint(ep):
                key = f"{ep.method}:{ep.path}"
                if key not in seen_ep:
                    seen_ep.add(key)
                    endpoints.append(ep)

        # Phase 4: Secrets
        secrets = self._extract_secrets(code, source_url)

        # Phase 5: Feature Flags
        flags = self._extract_flags(code, source_url)

        return ParseResult(
            endpoints=endpoints,
            secrets=secrets,
            flags=flags
        )

    def _is_valid_endpoint(self, ep: ExtractedEndpoint) -> bool:
        """Filters out XML namespaces, static asset scripts, empty paths, and keyword false positives."""
        path = ep.path.strip()

        # 1. Ignore empty, root single slash, or tiny fragment strings
        if not path or path == "/" or len(path) < 2 or path == ".html" or path == ".js":
            return False

        # 2. Ignore XML namespaces & web standards URLs (e.g. w3.org/1999/xhtml)
        if any(ns in path.lower() for ns in self.ignored_namespaces):
            return False

        # 3. Ignore external JS script tags & static asset files (.js, .css, .png, etc.)
        if path.lower().endswith(self.ignored_extensions) and ep.category != "Template View":
            return False

        # 4. GraphQL operation keyword filtering
        if ep.category == "GraphQL":
            if "?" in path:
                op_val = path.split("=")[-1].lower()
                if op_val in self.reserved_keywords or len(op_val) < 3:
                    return False

        return True

    def _walk_ast(self, tree: Any, source_url: str) -> List[ExtractedEndpoint]:
        endpoints = []

        def traverse(node):
            if not isinstance(node, dict) and not hasattr(node, "type"):
                return

            node_type = getattr(node, "type", None) or (node.get("type") if isinstance(node, dict) else None)

            if node_type == "CallExpression":
                ep = self._extract_from_callexpression(node, source_url)
                if ep:
                    endpoints.append(ep)

            if node_type == "Property":
                key_node = getattr(node, "key", None)
                val_node = getattr(node, "value", None)
                key_name = getattr(key_node, "name", "") or getattr(key_node, "value", "")
                if key_name in {"url", "path", "templateUrl"} and getattr(val_node, "type", "") == "Literal":
                    path_val = getattr(val_node, "value", "")
                    if isinstance(path_val, str) and (path_val.startswith("/") or path_val.endswith(".html")):
                        category = "Angular Route" if key_name != "templateUrl" else "Template View"
                        params = self._extract_params_from_path(path_val)
                        is_bola = any(p in path_val.lower() for p in ["{id}", "{candidateid}", "{key}", "{code}", "{pcid}", ":id", ":candidateid", ":key", ":code", ":pcid"])
                        endpoints.append(ExtractedEndpoint(
                            method="GET",
                            path=path_val,
                            source_url=source_url,
                            parameters=params,
                            category=category,
                            is_bola_candidate=is_bola
                        ))

            for key, val in (node.__dict__.items() if hasattr(node, "__dict__") else node.items()):
                if isinstance(val, list):
                    for item in val:
                        traverse(item)
                elif isinstance(val, (dict, object)) and (hasattr(val, "type") or (isinstance(val, dict) and "type" in val)):
                    traverse(val)

        traverse(tree)
        return endpoints

    def _extract_from_callexpression(self, node: Any, source_url: str) -> Optional[ExtractedEndpoint]:
        callee = getattr(node, "callee", None)
        args = getattr(node, "arguments", [])
        if not callee or not args:
            return None

        method = "GET"
        path = ""
        category = "REST"
        req_body: Dict[str, Any] = {}

        if getattr(callee, "type", "") == "MemberExpression":
            prop = getattr(callee, "property", None)
            if prop and hasattr(prop, "name"):
                prop_name = prop.name.lower()
                if prop_name in {"get", "post", "put", "patch", "delete"}:
                    method = prop_name.upper()
                    if method in {"POST", "PUT", "PATCH"} and len(args) > 1:
                        req_body = self._extract_object_structure(args[1])
                elif prop_name == "state" and len(args) > 1:
                    state_obj = args[1]
                    if getattr(state_obj, "type", "") == "ObjectExpression":
                        for p in getattr(state_obj, "properties", []):
                            p_key = getattr(getattr(p, "key", None), "name", "") or getattr(getattr(p, "key", None), "value", "")
                            p_val = getattr(getattr(p, "value", None), "value", "")
                            if p_key == "url" and isinstance(p_val, str):
                                category = "Angular Route"
                                path = p_val
                                break

        elif getattr(callee, "type", "") == "Identifier" and getattr(callee, "name", "") == "fetch":
            method = "GET"
            if len(args) > 1 and getattr(args[1], "type", "") == "ObjectExpression":
                for p in getattr(args[1], "properties", []):
                    key_name = getattr(getattr(p, "key", None), "name", "") or getattr(getattr(p, "key", None), "value", "")
                    if str(key_name).lower() == "method":
                        method_val = getattr(getattr(p, "value", None), "value", "")
                        if isinstance(method_val, str):
                            method = method_val.upper()
                    elif str(key_name).lower() == "body":
                        body_val_node = getattr(p, "value", None)
                        if getattr(body_val_node, "type", "") == "CallExpression":
                            body_args = getattr(body_val_node, "arguments", [])
                            if body_args:
                                req_body = self._extract_object_structure(body_args[0])
                        else:
                            req_body = self._extract_object_structure(body_val_node)

        elif getattr(callee, "type", "") == "Identifier" and getattr(callee, "name", "") == "WebSocket":
            category = "WebSocket"
            method = "WS"

        if not path and args:
            first_arg = args[0]
            if getattr(first_arg, "type", "") == "Literal":
                val = getattr(first_arg, "value", "")
                if isinstance(val, str):
                    path = val
            elif getattr(first_arg, "type", "") == "TemplateLiteral":
                path = self._reconstruct_template_literal(first_arg)

        if path and (path.startswith("/") or path.startswith("http") or path.startswith("ws") or path.endswith(".html")):
            params = self._extract_params_from_path(path)
            is_bola = any(p in path.lower() for p in ["{id}", "{candidateid}", "{key}", "{code}", "{pcid}", ":id", ":candidateid", ":key", ":code", ":pcid"])
            return ExtractedEndpoint(
                method=method,
                path=path,
                source_url=source_url,
                parameters=params,
                request_body=req_body,
                category=category,
                is_bola_candidate=is_bola
            )

        return None

    def _extract_router_definitions(self, code: str, source_url: str) -> List[ExtractedEndpoint]:
        endpoints = []
        url_matches = re.findall(r'url\s*:\s*["\']([^"\'\s]+)["\']', code)
        for u in set(url_matches):
            if u.startswith("/") or u.startswith("http"):
                params = self._extract_params_from_path(u)
                is_bola = any(p in u.lower() for p in [":candidateid", ":key", ":code", ":pcid", ":id", "{id}"])
                endpoints.append(ExtractedEndpoint(
                    method="GET",
                    path=u,
                    source_url=source_url,
                    parameters=params,
                    category="Angular Route",
                    is_bola_candidate=is_bola
                ))

        tpl_matches = re.findall(r'templateUrl\s*:\s*["\']([^"\'\s]+)["\']', code)
        for t in set(tpl_matches):
            endpoints.append(ExtractedEndpoint(
                method="GET",
                path=t,
                source_url=source_url,
                category="Template View",
                is_bola_candidate=False
            ))

        svc_matches = re.findall(r'([a-zA-Z0-9_]+Service|[a-zA-Z0-9_]+AccountService)\.([a-zA-Z0-9_]+)\(', code)
        for svc, fn in set(svc_matches):
            endpoints.append(ExtractedEndpoint(
                method="GET/POST",
                path=f"ServiceCall: {svc}.{fn}()",
                source_url=source_url,
                category="Service Method",
                is_bola_candidate=False
            ))

        return endpoints

    def _extract_object_structure(self, node: Any) -> Dict[str, Any]:
        res: Dict[str, Any] = {}
        if not node:
            return res

        node_type = getattr(node, "type", "")
        if node_type == "ObjectExpression":
            for p in getattr(node, "properties", []):
                key = getattr(p, "key", None)
                val = getattr(p, "value", None)
                key_name = getattr(key, "name", "") or getattr(key, "value", "")
                if key_name:
                    val_type = getattr(val, "type", "")
                    if val_type == "Literal":
                        res[str(key_name)] = getattr(val, "value", "EXAMPLE_VALUE")
                    elif val_type == "Identifier":
                        res[str(key_name)] = f"<{getattr(val, 'name', 'string')}>"
                    elif val_type == "ObjectExpression":
                        res[str(key_name)] = self._extract_object_structure(val)
                    else:
                        res[str(key_name)] = "<string>"
        elif node_type == "Identifier":
            res["payload"] = f"<{getattr(node, 'name', 'data_object')}>"
        return res

    def _reconstruct_template_literal(self, node: Any) -> str:
        quasis = getattr(node, "quasis", [])
        result = ""
        for q in quasis:
            raw = getattr(getattr(q, "value", None), "raw", "")
            result += raw
            if not getattr(q, "tail", True):
                result += "{param}"
        return result

    def _regex_fallback(self, code: str, source_url: str) -> List[ExtractedEndpoint]:
        endpoints = []
        rest_matches = re.findall(r'["\'`](/(?:api|v[0-9]+|graphql|rest|auth|v1|v2|users|admin|documents|reports|user|search|resume|myspace|candidate|organization|definition|student|language)[^\s"\'\`]*)["\'`]', code)
        for match in set(rest_matches):
            clean_path = re.sub(r'\$\{([^}]+)\}', r'{\1}', match)
            params = self._extract_params_from_path(clean_path)
            
            method = "GET"
            req_body = {}
            if "delete" in clean_path.lower():
                method = "DELETE"
            elif "update" in clean_path.lower() or "edit" in clean_path.lower():
                method = "PUT"
                req_body = {"id": "<id>", "data": "<update_payload>"}
            elif "create" in clean_path.lower() or "add" in clean_path.lower() or "post" in clean_path.lower():
                method = "POST"
                req_body = {"name": "<string>", "description": "<string>"}

            is_bola = any(p in clean_path.lower() for p in ["{id}", "{candidateid}", "{key}", "{code}", "{pcid}", ":id", ":candidateid", ":key", ":code", ":pcid"])
            endpoints.append(ExtractedEndpoint(
                method=method,
                path=clean_path,
                source_url=source_url,
                parameters=params,
                request_body=req_body,
                category="REST",
                is_bola_candidate=is_bola
            ))

        # GraphQL Mutation/Query matcher with keyword exclusion
        gql_matches = re.findall(r'(?:mutation|query)\s+([A-Za-z0-9_]+)', code)
        for op in set(gql_matches):
            if op.lower() not in self.reserved_keywords and len(op) > 2:
                endpoints.append(ExtractedEndpoint(
                    method="POST",
                    path=f"/graphql?op={op}",
                    source_url=source_url,
                    parameters=[op],
                    request_body={"query": f"query {op} {{ ... }}", "variables": {}},
                    category="GraphQL",
                    is_bola_candidate=False
                ))

        ws_matches = re.findall(r'["\'`](wss?://[^\s"\'\`]+)["\'`]', code)
        for ws in set(ws_matches):
            endpoints.append(ExtractedEndpoint(
                method="WS",
                path=ws,
                source_url=source_url,
                category="WebSocket",
                is_bola_candidate=False
            ))

        return endpoints

    def _extract_secrets(self, code: str, source_url: str) -> List[ExtractedSecret]:
        secrets: List[ExtractedSecret] = []
        seen = set()
        for label, pattern in self.secret_patterns:
            matches = re.findall(pattern, code)
            for m in matches:
                val = m if isinstance(m, str) else m[0]
                key = f"{label}:{val}"
                if key not in seen:
                    seen.add(key)
                    secrets.append(ExtractedSecret(
                        secret_type=label,
                        key_name=label,
                        value=val,
                        source_url=source_url
                    ))
        return secrets

    def _extract_flags(self, code: str, source_url: str) -> List[ExtractedFlag]:
        flags: List[ExtractedFlag] = []
        seen = set()
        for label, pattern in self.flag_patterns:
            matches = re.finditer(pattern, code)
            for m in matches:
                snippet = m.group(0)
                val = m.group(1) if m.groups() else snippet
                key = f"{label}:{val}"
                if key not in seen:
                    seen.add(key)
                    flags.append(ExtractedFlag(
                        flag_type=label,
                        name=val,
                        snippet=snippet,
                        source_url=source_url
                    ))
        return flags

    def _extract_params_from_path(self, path: str) -> List[str]:
        path_params = re.findall(r'\{([^}]+)\}|:([A-Za-z0-9_]+)', path)
        flattened = [p[0] or p[1] for p in path_params if p[0] or p[1]]
        if "?" in path:
            query_str = path.split("?")[1]
            query_params = [q.split("=")[0] for q in query_str.split("&") if "=" in q]
            flattened.extend(query_params)
        return list(set(flattened))
