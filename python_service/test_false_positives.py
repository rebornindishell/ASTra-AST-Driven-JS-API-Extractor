from parser import JSParser

false_positive_js = """
var ns = "http://www.w3.org/1999/xhtml";
var root = "/";
var scriptUrl = "https://cdn.mindrocketsapis.com/client/ehs/integrator.js";
var ext = ".html";
var q = "query of something";
"""

def test_fp():
    print("[*] Testing False Positive Exclusion Rules...")
    parser = JSParser()
    res = parser.parse_code(false_positive_js, source_url="https://example.com/test.js")

    print(f"[+] Remaining Endpoints after Filtering: {len(res.endpoints)}")
    for ep in res.endpoints:
        print(f"  - [{ep.category}] {ep.method} {ep.path}")

    if len(res.endpoints) == 0:
        print("[+] SUCCESS: All 5 false positive patterns were correctly filtered out!")
    else:
        print("[!] Warning: Some false positives were not filtered.")

if __name__ == "__main__":
    test_fp()
