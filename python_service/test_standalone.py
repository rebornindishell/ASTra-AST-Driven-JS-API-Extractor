import json
from parser import JSParser
from normalizer import SchemaNormalizer

sample_minified_js = """
function getUserProfile(userId) {
    return axios.get('/api/users/' + userId + '/profile');
}
function updateDocument(docId, data) {
    return fetch(`/api/documents/${docId}`, { method: 'PUT', body: JSON.stringify(data) });
}
const gqlQuery = "query GetUserOrders { orders { id total } }";
const ws = new WebSocket("wss://target.example/realtime/notifications");
"""

def test_parser():
    print("[*] Running JSParser standalone test...")
    parser = JSParser()
    normalizer = SchemaNormalizer()

    result = parser.parse_code(sample_minified_js, source_url="https://target.example/static/js/main.8a91f.js")
    endpoints = result.endpoints
    print(f"[+] Extracted {len(endpoints)} endpoints:")
    for ep in endpoints:
        print(f"  - [{ep.category}] {ep.method} {ep.path} (BOLA: {ep.is_bola_candidate}, Params: {ep.parameters})")

    if result.secrets:
        print(f"\n[+] Discovered {len(result.secrets)} secrets:")
        for s in result.secrets:
            print(f"  - [{s.secret_type}] {s.key_name}: {s.value}")

    openapi_spec = normalizer.to_openapi(endpoints)
    print("\n[+] Generated OpenAPI Specification:")
    print(json.dumps(openapi_spec, indent=2))

if __name__ == "__main__":
    test_parser()
