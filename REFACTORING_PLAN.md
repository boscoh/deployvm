# Deploy VM Refactoring Plan

**Current State:** Single 2,332-line file (`deploy_vm.py`)
**Goal:** Modular architecture with clear separation of concerns
**Benefits:** Better testability, maintainability, and extensibility

---

## Proposed Module Structure

```
deploy_vm/
├── __init__.py              # Package exports
├── __main__.py              # Entry point for python -m deploy_vm
├── cli.py                   # CLI app setup and command registration (~100 LOC)
│
├── core/                    # Low-level utilities
│   ├── __init__.py
│   ├── logging.py           # log(), warn(), error() (~20 LOC)
│   ├── shell.py             # run_cmd(), run_cmd_json() (~30 LOC)
│   └── ssh.py               # SSH/Fabric wrappers, rsync (~130 LOC)
│
├── models/                  # Data models
│   ├── __init__.py
│   ├── instance.py          # Instance dataclass, JSON load/save (~100 LOC)
│   └── app.py               # App dataclass, app management (~50 LOC)
│
├── providers/               # Cloud provider abstraction
│   ├── __init__.py
│   ├── base.py              # Provider Protocol (~30 LOC)
│   ├── digitalocean.py      # DigitalOcean implementation (~200 LOC)
│   ├── aws.py               # AWS implementation (~450 LOC)
│   └── factory.py           # get_provider() factory (~30 LOC)
│
├── network/                 # Network operations
│   ├── __init__.py
│   ├── validation.py        # IP/DNS/HTTP validation (~100 LOC)
│   ├── dns.py               # DNS setup logic (~50 LOC)
│   └── nginx.py             # Nginx config generation and setup (~160 LOC)
│
├── server/                  # Server management
│   ├── __init__.py
│   ├── setup.py             # Bootstrap new servers (~130 LOC)
│   ├── firewall.py          # UFW management (~30 LOC)
│   └── verification.py      # Health checks (~90 LOC)
│
├── apps/                    # Application deployment
│   ├── __init__.py
│   ├── base.py              # Base deployment patterns (~100 LOC)
│   ├── nuxt.py              # Nuxt-specific deployment (~200 LOC)
│   └── fastapi.py           # FastAPI-specific deployment (~200 LOC)
│
└── commands/                # CLI command handlers
    ├── __init__.py
    ├── instance.py          # instance_app commands (~150 LOC)
    ├── nginx_cmd.py         # nginx_app commands (~100 LOC)
    ├── nuxt_cmd.py          # nuxt_app commands (~150 LOC)
    └── fastapi_cmd.py       # fastapi_app commands (~150 LOC)
```

**Total Estimated LOC:** ~2,400 (slight increase due to imports/module overhead)

---

## Migration Strategy

### Phase 1: Core Infrastructure (Low Risk)
**Goal:** Extract foundational utilities with minimal dependencies

1. **Create package structure**
   - `deploy_vm/__init__.py`
   - `deploy_vm/__main__.py` → entry point
   - Move constants (PROVIDER_OPTIONS, timeouts) to `deploy_vm/constants.py`

2. **Extract core utilities** (Day 1)
   - `core/logging.py` ← log(), warn(), error()
   - `core/shell.py` ← run_cmd(), run_cmd_json()
   - `core/ssh.py` ← ssh(), ssh_script(), ssh_write_file(), rsync(), etc.
   - **Risk:** Low (pure functions, minimal state)
   - **Testing:** Unit tests for each function

3. **Extract data models** (Day 1)
   - `models/instance.py` ← load_instance(), save_instance(), Instance dataclass
   - `models/app.py` ← get_instance_apps(), add_app_to_instance(), App dataclass
   - **Risk:** Low (self-contained)
   - **Testing:** JSON load/save round-trips

### Phase 2: Network Layer (Medium Risk)
**Goal:** Isolate network operations

4. **Extract network utilities** (Day 2)
   - `network/validation.py` ← is_valid_ip(), resolve_dns_a(), check_http_status()
   - `network/dns.py` ← ensure_dns_matches() + provider DNS logic
   - `network/nginx.py` ← generate_nginx_server_block(), setup_nginx_ip(), setup_nginx_ssl()
   - **Risk:** Medium (depends on SSH, providers)
   - **Testing:** Mock DNS/HTTP responses

### Phase 3: Cloud Providers (Medium Risk)
**Goal:** Isolate provider-specific code

5. **Extract providers** (Day 3)
   - `providers/base.py` ← Provider Protocol
   - `providers/digitalocean.py` ← DigitalOceanProvider
   - `providers/aws.py` ← AWSProvider
   - `providers/factory.py` ← get_provider(), get_aws_config()
   - **Risk:** Medium (complex logic, external APIs)
   - **Testing:** Mock doctl/boto3 calls

### Phase 4: Server Management (Low-Medium Risk)
**Goal:** Server setup and maintenance

6. **Extract server utilities** (Day 4)
   - `server/setup.py` ← setup_server()
   - `server/firewall.py` ← ensure_web_firewall()
   - `server/verification.py` ← verify_instance()
   - **Risk:** Low-Medium (depends on SSH)
   - **Testing:** Integration tests with mock SSH

### Phase 5: Application Deployment (High Risk)
**Goal:** Refactor deployment logic with shared patterns

7. **Create base deployment class** (Day 5)
   - `apps/base.py`:
     ```python
     class AppDeployment:
         def __init__(self, instance_data, provider_name):
             ...

         def compute_source_hash(self, local_path): ...
         def detect_ssh_user(self): ...
         def select_app(self, app_type, app_name=None): ...
         def sync_code(self, local, remote, exclude): ...
         def restart_service(self): ...  # abstract
         def check_status(self): ...     # abstract
         def view_logs(self): ...        # abstract
     ```

8. **Extract Nuxt deployment** (Day 6)
   - `apps/nuxt.py` ← NuxtDeployment(AppDeployment)
   - PM2-specific logic
   - Node version detection

9. **Extract FastAPI deployment** (Day 6)
   - `apps/fastapi.py` ← FastAPIDeployment(AppDeployment)
   - Supervisor-specific logic
   - UV package management

   **Risk:** High (complex orchestration, many dependencies)
   **Testing:** End-to-end tests on real instances

### Phase 6: CLI Commands (Low Risk)
**Goal:** Thin command handlers that orchestrate modules

10. **Extract command handlers** (Day 7)
    - `commands/instance.py` ← create_instance(), delete_instance(), list_instances()
    - `commands/nginx_cmd.py` ← nginx setup commands
    - `commands/nuxt_cmd.py` ← deploy_nuxt(), sync_nuxt(), restart_pm2()
    - `commands/fastapi_cmd.py` ← deploy_fastapi(), sync_fastapi(), restart_supervisor()
    - `cli.py` ← cyclopts app registration only

    **Risk:** Low (thin wrappers)
    **Testing:** CLI integration tests

---

## Critical Bugs to Fix During Refactoring

### Bug 1: Undefined `provider` Variable
**Location:** Lines 2011, 2024 in `deploy_nuxt()` and `deploy_fastapi()`

**Issue:**
```python
# deploy_vm.py:2011
ensure_dns_matches(
    ip=instance_data["ip"],
    domain=domain,
    provider=provider,  # ❌ Variable 'provider' not defined
)
```

**Fix:** Replace with `provider_name` parameter or get from `instance_data["provider"]`

```python
ensure_dns_matches(
    ip=instance_data["ip"],
    domain=domain,
    provider=instance_data["provider"],  # ✅ Use stored provider
)
```

### Bug 2: Inconsistent SSH User Detection
**Pattern:** Repeated logic in 5+ places

**Fix:** Consolidate into utility:
```python
def get_ssh_user(provider_name: str) -> str:
    """Get default SSH user for provider.

    :param provider_name: Cloud provider name
    :return: SSH username (ubuntu for AWS, root for DigitalOcean)
    """
    return "ubuntu" if provider_name == "aws" else "root"
```

---

## Code Deduplication Opportunities

### 1. App Selection Logic (4 occurrences)
**Extract to:**
```python
# apps/base.py
def select_app(instance_data: dict, app_type: str, app_name: str = None) -> dict:
    """Find app by type and optional name.

    :param instance_data: Instance data dict
    :param app_type: App type (nuxt or fastapi)
    :param app_name: Optional app name (required if multiple apps)
    :return: App dict with name, type, port
    :raises: Error if app not found or multiple apps without name
    """
    apps = get_instance_apps(instance_data)
    matching = [a for a in apps if a["type"] == app_type]

    if not matching:
        error(f"No {app_type} app found")

    if len(matching) == 1 and not app_name:
        return matching[0]

    if not app_name:
        error(f"Multiple {app_type} apps found. Use --app-name")

    app = next((a for a in matching if a["name"] == app_name), None)
    if not app:
        error(f"App '{app_name}' not found")

    return app
```

### 2. Change Detection (~70% similar between Nuxt/FastAPI)
**Extract to:**
```python
# apps/base.py
class AppDeployment:
    def should_rebuild(self, local_path: str, hash_file: str) -> bool:
        """Check if source changed since last build."""
        new_hash = self.compute_source_hash(local_path)
        try:
            old_hash = ssh(self.ip, f"cat {hash_file}", user=self.ssh_user)
            if new_hash == old_hash:
                log(f"Source unchanged ({new_hash[:8]}), skipping rebuild")
                return False
        except:
            pass
        return True
```

---

## Testing Strategy

### Unit Tests (Day 1-7, ongoing)
- `tests/unit/test_utils.py` ← logging, shell commands
- `tests/unit/test_instance.py` ← JSON load/save
- `tests/unit/test_validation.py` ← IP/DNS/HTTP checks
- `tests/unit/test_nginx.py` ← Config generation

### Integration Tests (Day 8-9)
- `tests/integration/test_providers.py` ← Mock cloud APIs
- `tests/integration/test_ssh.py` ← Mock Fabric connections
- `tests/integration/test_deployment.py` ← Mock end-to-end flow

### E2E Tests (Day 10)
- `tests/e2e/test_nuxt_deploy.py` ← Real DigitalOcean instance
- `tests/e2e/test_fastapi_deploy.py` ← Real AWS instance

**Coverage Goal:** 80%+ after refactoring

---

## Rollback Plan

### Safety Measures
1. **Keep original file** as `deploy_vm_legacy.py`
2. **Create feature branch** `refactor/modular-structure`
3. **Test each phase** before proceeding
4. **Deploy to staging** before production

### Rollback Steps (if issues arise)
```bash
# Revert to original single-file version
git checkout main deploy_vm.py
uv pip install -e .
```

---

## Migration Checklist

- [ ] Phase 1: Core utilities extracted
- [ ] Phase 2: Network layer extracted
- [ ] Phase 3: Providers extracted
- [ ] Phase 4: Server management extracted
- [ ] Phase 5: App deployment base class created
- [ ] Phase 6: Nuxt/FastAPI deployments refactored
- [ ] Phase 7: CLI commands extracted
- [ ] Bug fixes applied (undefined `provider`, SSH user detection)
- [ ] Unit tests passing (80%+ coverage)
- [ ] Integration tests passing
- [ ] E2E tests passing on DigitalOcean
- [ ] E2E tests passing on AWS
- [ ] Documentation updated
- [ ] Original `deploy_vm.py` archived

---

## Estimated Timeline

| Phase | Duration | Risk | Can Run in Parallel |
|-------|----------|------|---------------------|
| Phase 1: Core | 4-6 hours | Low | No (foundation) |
| Phase 2: Network | 2-4 hours | Medium | After Phase 1 |
| Phase 3: Providers | 4-6 hours | Medium | After Phase 1 |
| Phase 4: Server | 2-3 hours | Low | After Phase 1 |
| Phase 5: App Base | 3-4 hours | High | After Phase 1-4 |
| Phase 6: Deployments | 4-6 hours | High | After Phase 5 |
| Phase 7: CLI | 2-3 hours | Low | After Phase 1-6 |
| Testing | 6-8 hours | - | Throughout |
| **TOTAL** | **27-40 hours** | - | Over 2-3 weeks |

---

## Benefits After Refactoring

### For Development
- **Testability:** Each module can be tested in isolation
- **Maintainability:** Changes localized to specific modules
- **Extensibility:** Easy to add new providers or app types
- **Code Reuse:** Shared patterns in base classes

### For Users
- **Reliability:** Better test coverage = fewer bugs
- **Performance:** Same (no runtime impact)
- **Features:** Easier to add new capabilities

### Metrics
- **Current:** 1 file, 2,332 lines
- **After:** ~15 modules, avg 150 lines/module
- **Test Coverage:** 0% → 80%+
- **Cyclomatic Complexity:** Reduced by ~40%

---

## Open Questions

1. **Backwards Compatibility:** Keep `deploy-vm` CLI command? (Yes, via `__main__.py`)
2. **Config File:** Should we add `deploy-vm.toml` for defaults? (Future enhancement)
3. **Plugin System:** Allow custom providers/app types? (Future enhancement)
4. **Async Support:** Use asyncio for parallel operations? (v2.0 consideration)

---

## Next Steps

1. **Review this plan** with stakeholders
2. **Create feature branch** `refactor/modular-structure`
3. **Start with Phase 1** (low-risk utilities)
4. **Iterate with testing** after each phase
5. **Merge when all tests pass**
