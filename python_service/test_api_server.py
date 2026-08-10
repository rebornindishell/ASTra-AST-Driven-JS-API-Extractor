import time
import httpx

BASE_URL = "http://127.0.0.1:8000"

def test_api():
    print("[*] Testing FastAPI REST Server endpoints...")
    client = httpx.Client(timeout=10.0)

    # 1. Health check
    res = client.get(f"{BASE_URL}/")
    print(f"[+] Health check GET /: {res.status_code} -> {res.json()}")

    # 2. Parse JS snippet
    sample_js = """
    async function getOrders(tenantId) {
        return axios.get(`/api/v1/tenants/${tenantId}/orders?status=active`);
    }
    async function deleteUser(id) {
        return fetch(`/api/users/${id}`, { method: 'DELETE' });
    }
    """
    parse_res = client.post(f"{BASE_URL}/parse", json={"source": sample_js, "url": "https://example.com/bundle.js"})
    print(f"[+] POST /parse: {parse_res.status_code} -> Count: {parse_res.json()['count']}")
    for ep in parse_res.json()["endpoints"]:
        print(f"    Extracted: {ep['method']} {ep['path']}")

    # 3. Export OpenAPI
    openapi_res = client.get(f"{BASE_URL}/export/openapi")
    print(f"[+] GET /export/openapi: {openapi_res.status_code} -> Paths found: {list(openapi_res.json()['paths'].keys())}")

    # 4. Export Postman
    postman_res = client.get(f"{BASE_URL}/export/postman")
    print(f"[+] GET /export/postman: {postman_res.status_code} -> Collection Name: {postman_res.json()['info']['name']}")

if __name__ == "__main__":
    test_api()
