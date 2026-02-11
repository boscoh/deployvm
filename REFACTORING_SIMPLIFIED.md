# Deploy VM Refactoring - Simplified Plan

**Goal:** Break 2,332-line file into 3-4 logical modules without excessive overhead

---

## Proposed Structure (4 Modules)

```
deploy_vm/
├── __init__.py              # Package exports
├── __main__.py              # Entry point
├── cli.py                   # CLI setup + all commands (~600 LOC)
├── providers.py             # Cloud providers (DO/AWS) (~700 LOC)
├── server.py                # Server setup, SSH, nginx, DNS (~600 LOC)
└── apps.py                  # Nuxt/FastAPI deployment logic (~500 LOC)
```

**Total:** ~2,400 LOC across 4 files (avg 600 lines each)

---

## Module Breakdown

### 1. `cli.py` - Command Interface (~600 LOC)
**What it contains:**
- Cyclopts app setup and command registration
- All command handler functions:
  - `instance create/delete/list/apps/verify`
  - `nginx ip/ssl`
  - `nuxt deploy/sync/restart/status/logs`
  - `fastapi deploy/sync/restart/status/logs`
- Utilities: `log()`, `warn()`, `error()`
- Instance JSON: `load_instance()`, `save_instance()`
- Helper functions: `resolve_ip()`, `resolve_instance()`

**Imports:**
```python
from .providers import get_provider, DigitalOceanProvider, AWSProvider
from .server import setup_server, setup_nginx_ip, setup_nginx_ssl, verify_instance
from .apps import NuxtApp, FastAPIApp
```

### 2. `providers.py` - Cloud Infrastructure (~700 LOC)
**What it contains:**
- `Provider` Protocol (interface)
- `DigitalOceanProvider` class
- `AWSProvider` class
- `get_provider()` factory function
- `get_aws_config()` helper
- `PROVIDER_OPTIONS` constant

**Key methods:**
- `validate_auth()`, `validate_config()`
- `instance_exists()`, `create_instance()`, `delete_instance()`, `list_instances()`
- `setup_dns()`, `cleanup_resources()`

### 3. `server.py` - Server Operations (~600 LOC)
**What it contains:**
- **SSH layer:** `ssh()`, `ssh_script()`, `ssh_as_user()`, `ssh_write_file()`
- **File transfer:** `rsync()`, `_rsync_tar_fallback()`
- **Network validation:** `is_valid_ip()`, `resolve_dns_a()`, `check_http_status()`
- **Server setup:** `setup_server()`, `ensure_web_firewall()`
- **DNS/Nginx:** `ensure_dns_matches()`, `generate_nginx_server_block()`, `setup_nginx_ip()`, `setup_nginx_ssl()`
- **Health checks:** `verify_instance()`
- **Shell commands:** `run_cmd()`, `run_cmd_json()`

**Key responsibilities:**
- All remote execution
- Network validation
- Web server configuration
- Server bootstrapping

### 4. `apps.py` - Application Deployment (~500 LOC)
**What it contains:**
- **Base class:** `BaseApp` with shared logic
  - `compute_source_hash()`
  - `detect_ssh_user()`
  - `select_app()`
- **Nuxt class:** `NuxtApp(BaseApp)`
  - `sync()`, `restart()`, `status()`, `logs()`
  - `detect_node_version()`, `generate_pm2_config()`
- **FastAPI class:** `FastAPIApp(BaseApp)`
  - `sync()`, `restart()`, `status()`, `logs()`
  - Supervisor config generation

**Key pattern:**
```python
class BaseApp:
    def __init__(self, instance_data, provider_name):
        self.instance = instance_data
        self.ip = instance_data["ip"]
        self.ssh_user = "ubuntu" if provider_name == "aws" else "root"

    def compute_source_hash(self, local_path): ...
    def select_app(self, app_name=None): ...

class NuxtApp(BaseApp):
    APP_TYPE = "nuxt"

    def sync(self, local_path, ...): ...
    def restart(self, app_name=None): ...
```

---

## Migration Strategy (3 Phases)

### Phase 1: Extract Providers (~2 hours)
**Low risk - isolated from rest of code**

1. Create `deploy_vm/` directory
2. Create `providers.py` with:
   - Copy Provider Protocol
   - Copy DigitalOceanProvider class
   - Copy AWSProvider class
   - Copy get_provider(), get_aws_config()
3. Test: Import and create provider instances

### Phase 2: Extract Server Operations (~3 hours)
**Medium risk - used everywhere**

1. Create `server.py` with:
   - All SSH functions
   - All network validation
   - Server setup functions
   - Nginx/DNS functions
   - Health verification
2. Test: Import and run SSH commands

### Phase 3: Extract Apps + Refactor CLI (~4 hours)
**Medium-high risk - orchestration logic**

1. Create `apps.py`:
   - Extract common patterns to BaseApp
   - Create NuxtApp class
   - Create FastAPIApp class
2. Update `cli.py`:
   - Command handlers use new imports
   - Fix bugs (undefined `provider` variable)
3. Create `__init__.py` and `__main__.py`
4. Update `pyproject.toml` entry point

**Total Time:** ~9 hours (1 day)

---

## What Gets Shared/Simplified

### Shared in BaseApp
```python
class BaseApp:
    def compute_source_hash(self, local_path):
        """Compute MD5 hash of source files."""
        # ~20 lines (currently duplicated)

    def detect_ssh_user(self):
        """Get SSH user based on provider."""
        return "ubuntu" if self.provider == "aws" else "root"

    def select_app(self, app_name=None):
        """Find app by type, handle multiple apps."""
        # ~15 lines (currently appears 4 times)

    def should_rebuild(self, local_path, hash_file):
        """Check if source changed since last build."""
        # ~10 lines (currently duplicated)
```

### Stays in Subclasses
- **NuxtApp:** PM2 config, Node.js detection, build commands
- **FastAPIApp:** Supervisor config, uv/venv, Python-specific logic

---

## Imports After Refactoring

### In user code (no change)
```bash
# CLI still works identically
deploy-vm instance create myapp
deploy-vm nuxt deploy myapp ...
```

### In `cli.py`
```python
from deploy_vm.providers import get_provider
from deploy_vm.server import (
    setup_server, setup_nginx_ssl, verify_instance,
    ssh, rsync, ensure_dns_matches
)
from deploy_vm.apps import NuxtApp, FastAPIApp
```

### For programmatic use
```python
# Keep backwards compatibility
from deploy_vm import create_instance, deploy_nuxt

# Or use new imports
from deploy_vm.cli import create_instance
from deploy_vm.apps import NuxtApp
```

---

## Critical Bugs to Fix

### Bug 1: Undefined `provider` in deploy functions
**Lines:** 2011, 2024

**Current (broken):**
```python
def deploy_nuxt(..., provider_name: str, ...):
    ...
    ensure_dns_matches(
        ip=instance_data["ip"],
        domain=domain,
        provider=provider,  # ❌ Undefined
    )
```

**Fix:**
```python
ensure_dns_matches(
    ip=instance_data["ip"],
    domain=domain,
    provider=instance_data["provider"],  # ✅ Use from instance data
)
```

### Bug 2: Inconsistent SSH user detection
**Pattern:** Repeated in 5+ places

**Fix:** Centralize in BaseApp:
```python
class BaseApp:
    def __init__(self, instance_data):
        self.ssh_user = (
            "ubuntu" if instance_data["provider"] == "aws" else "root"
        )
```

---

## File Size Comparison

| Current | After | Reduction |
|---------|-------|-----------|
| deploy_vm.py: 2,332 lines | cli.py: ~600 lines | -74% |
| | providers.py: ~700 lines | |
| | server.py: ~600 lines | |
| | apps.py: ~500 lines | |
| **Total: 2,332** | **Total: ~2,400** | +3% (imports) |

**Average lines per file:** 600 (down from 2,332)

---

## Testing Strategy

### Minimal Testing Approach
**Don't need 80% coverage to ship - just validate refactoring didn't break anything**

1. **Manual smoke tests** (30 min)
   ```bash
   # Test each command once
   deploy-vm instance create test-refactor
   deploy-vm instance list
   deploy-vm instance delete test-refactor
   ```

2. **Import tests** (10 min)
   ```python
   # test_imports.py
   def test_imports():
       from deploy_vm import cli, providers, server, apps
       from deploy_vm.providers import get_provider
       from deploy_vm.apps import NuxtApp, FastAPIApp
   ```

3. **Regression test** (if you have existing instances)
   ```bash
   # Test on real instance
   deploy-vm nuxt sync existing-instance /path/to/app
   deploy-vm fastapi restart existing-api
   ```

**Total testing time:** ~1 hour

---

## Migration Checklist

**Phase 1: Providers (2 hours)**
- [ ] Create `deploy_vm/` directory structure
- [ ] Create `providers.py` with all provider classes
- [ ] Test imports: `from deploy_vm.providers import get_provider`

**Phase 2: Server (3 hours)**
- [ ] Create `server.py` with SSH/nginx/DNS functions
- [ ] Test imports: `from deploy_vm.server import ssh`

**Phase 3: Apps + CLI (4 hours)**
- [ ] Create `apps.py` with BaseApp, NuxtApp, FastAPIApp
- [ ] Update `cli.py` with new imports
- [ ] Create `__init__.py` and `__main__.py`
- [ ] Update `pyproject.toml` entry point
- [ ] Fix bug: undefined `provider` variable
- [ ] Fix bug: inconsistent SSH user detection

**Testing (1 hour)**
- [ ] Import tests pass
- [ ] Smoke test: create/list/delete instance
- [ ] Regression test: deploy to real instance (if available)

**Cleanup**
- [ ] Archive original: `git mv deploy_vm.py deploy_vm_legacy.py`
- [ ] Commit: "Refactor into 4 modules"
- [ ] Push to remote

**Total time: ~10 hours (1-2 days)**

---

## Rollback Plan

If issues arise:
```bash
# Restore original single file
git checkout HEAD~1 deploy_vm.py
git checkout HEAD~1 pyproject.toml
rm -rf deploy_vm/
```

---

## Benefits vs Cost

### Benefits
✅ **600 lines/file** instead of 2,332 (easier to navigate)
✅ **Eliminates duplication** (~60% overlap between Nuxt/FastAPI)
✅ **Fixes 2 bugs** (undefined variable, SSH user)
✅ **Easier to extend** (new provider = 1 file, not editing 2,332-line file)

### Costs
⚠️ **+3% LOC** due to imports (2,332 → 2,400)
⚠️ **10 hours work** to migrate
⚠️ **Import overhead** (+10ms startup, negligible)

### Not Doing (to save time)
❌ No test suite (test manually instead)
❌ No deep abstraction (keep it simple)
❌ No plugin system (YAGNI)
❌ No config file (use env vars)

---

## Simpler Alternative: Just Fix Bugs

**If refactoring is too much, just fix the 2 critical bugs:**

1. **Fix undefined `provider`** (5 min)
   - Lines 2011, 2024: Change `provider=provider` → `provider=instance_data["provider"]`

2. **Add SSH user helper** (10 min)
   ```python
   def get_ssh_user(provider_name: str) -> str:
       return "ubuntu" if provider_name == "aws" else "root"
   ```
   - Replace 5+ occurrences with function call

**Total time: 15 minutes**

This gets you 80% of the reliability benefit with 2% of the effort.

---

## Decision: What to Do?

**Option A:** Full refactoring (4 modules, ~10 hours)
- Best long-term maintainability
- Eliminates code duplication
- Easier to extend

**Option B:** Just fix bugs (2 fixes, ~15 minutes)
- Minimal effort
- Keeps existing structure
- Good enough for now

**Option C:** Something in between
- Extract just providers.py (~2 hours)
- Fix bugs (~15 min)
- Leave rest as-is

Your call!
