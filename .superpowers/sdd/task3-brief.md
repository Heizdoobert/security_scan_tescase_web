# Task 3: Module Reorganization + Loader + main.py

Move all modules from websec_test/modules/*.py into classified subfolders. Update loader for subfolder discovery. Update main.py to use CheckTreeBuilder.

## Create these init files:

websec_test/modules/authentication/__init__.py:
from .auth import AuthModule
from .authz import AuthorizationModule
from .csrf import CSRFModule

websec_test/modules/injection/__init__.py:
from .sqli import SqliModule
from .xss import XssModule
from .nosql import NosqlModule
from .cmd_injection import CmdInjectionModule

websec_test/modules/configuration/__init__.py:
from .headers import HeadersModule
from .cookies import CookiesModule
from .ssl_tls import SslTlsModule
from .cors import CorsModule
from .disclosure import DisclosureModule
from .methods import MethodsModule

## Move files (git mv):

mkdir websec_test/modules/authentication websec_test/modules/injection websec_test/modules/configuration

git mv websec_test/modules/auth.py websec_test/modules/authentication/auth.py
git mv websec_test/modules/authz.py websec_test/modules/authentication/authz.py
git mv websec_test/modules/csrf.py websec_test/modules/authentication/csrf.py
git mv websec_test/modules/sqli.py websec_test/modules/injection/sqli.py
git mv websec_test/modules/xss.py websec_test/modules/injection/xss.py
git mv websec_test/modules/nosql.py websec_test/modules/injection/nosql.py
git mv websec_test/modules/cmd_injection.py websec_test/modules/injection/cmd_injection.py
git mv websec_test/modules/headers.py websec_test/modules/configuration/headers.py
git mv websec_test/modules/cookies.py websec_test/modules/configuration/cookies.py
git mv websec_test/modules/ssl_tls.py websec_test/modules/configuration/ssl_tls.py
git mv websec_test/modules/cors.py websec_test/modules/configuration/cors.py
git mv websec_test/modules/disclosure.py websec_test/modules/configuration/disclosure.py
git mv websec_test/modules/methods.py websec_test/modules/configuration/methods.py

## Update websec_test/engine/loader.py:

Replace with version using pkgutil.walk_packages() instead of iter_modules().
See the plan for exact code.

## Update websec_test/main.py:

Change import to include CheckTreeBuilder.
Change tree-building block:
- For modules with check_* methods: discover endpoints, build tree via CheckTreeBuilder
- For modules without: use ModuleAdapter (backward compat)

## Fix test imports:

All tests that import from websec_test.modules.* need new paths.
See plan for the full mapping.

## Run tests and commit
