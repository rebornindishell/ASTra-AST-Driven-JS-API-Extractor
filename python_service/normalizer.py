from typing import List, Dict, Any
from parser import ExtractedEndpoint

class SchemaNormalizer:
    def to_openapi(self, endpoints: List[ExtractedEndpoint], title: str = "Extracted JS API Inventory") -> Dict[str, Any]:
        paths: Dict[str, Any] = {}

        for ep in endpoints:
            path_key = ep.path.split("?")[0]
            if not path_key.startswith("/"):
                path_key = "/" + path_key

            if path_key not in paths:
                paths[path_key] = {}

            method_key = ep.method.lower()
            if method_key == "ws":
                method_key = "get"

            parameters = []
            for param in ep.parameters:
                parameters.append({
                    "name": param,
                    "in": "path" if f"{{{param}}}" in path_key else "query",
                    "required": True if f"{{{param}}}" in path_key else False,
                    "schema": {"type": "string"}
                })

            paths[path_key][method_key] = {
                "summary": f"Discovered endpoint via JS bundle ({ep.category})",
                "description": f"Source asset: {ep.source_url}",
                "parameters": parameters,
                "responses": {
                    "200": {
                        "description": "Successful response"
                    },
                    "401": {
                        "description": "Unauthorized access"
                    },
                    "403": {
                        "description": "Forbidden access"
                    }
                }
            }

        return {
            "openapi": "3.0.3",
            "info": {
                "title": title,
                "version": "1.0.0",
                "description": "API Schema automatically reverse-engineered from client-side JavaScript bundles."
            },
            "paths": paths
        }

    def to_postman(self, endpoints: List[ExtractedEndpoint], title: str = "JS Extracted API Collection") -> Dict[str, Any]:
        items = []

        for ep in endpoints:
            path_parts = [p for p in ep.path.split("?")[0].split("/") if p]
            
            query_items = []
            if "?" in ep.path:
                query_str = ep.path.split("?")[1]
                for pair in query_str.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        query_items.append({"key": k, "value": v})

            items.append({
                "name": f"{ep.method} {ep.path}",
                "request": {
                    "method": ep.method if ep.method != "WS" else "GET",
                    "header": [],
                    "url": {
                        "raw": "{{baseUrl}}" + ep.path,
                        "host": ["{{baseUrl}}"],
                        "path": path_parts,
                        "query": query_items
                    }
                },
                "response": []
            })

        return {
            "info": {
                "name": title,
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": items
        }
