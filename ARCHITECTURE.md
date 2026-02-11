# Deploy VM Architecture

## Current Architecture (Single File)

```
deploy_vm.py (2,332 lines)
├── Imports & Constants (100 lines)
├── Utilities (50 lines)
├── SSH Layer (120 lines)
├── Instance Data (134 lines)
├── Network Utils (93 lines)
├── Cloud Providers (671 lines)
│   ├── Provider Protocol
│   ├── DigitalOcean (187 lines)
│   └── AWS (439 lines)
├── Instance Commands (149 lines)
├── Health Checks (89 lines)
├── Server Setup (125 lines)
├── DNS/Nginx (158 lines)
├── Nuxt Deployment (307 lines)
└── FastAPI Deployment (290 lines)
```

**Issues:**
- Hard to test individual components
- High cognitive load (2,332 lines to understand)
- Duplicate code between deployment types
- Tight coupling between layers

---

## Proposed Architecture (Modular)

### Dependency Flow

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                           │
│              (cyclopts app, command routing)                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Command Handlers                        │
│    (instance, nginx_cmd, nuxt_cmd, fastapi_cmd)            │
└─────────────────────────────────────────────────────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   Instance    │    │     Apps      │    │    Network    │
│  Management   │    │  (Nuxt/API)   │    │  (DNS/Nginx)  │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                    ┌───────────────────┐
                    │   Server Setup    │
                    │  (Bootstrap/UFW)  │
                    └───────────────────┘
                              │
                ┌─────────────┼─────────────┐
                ▼             ▼             ▼
        ┌─────────────┐ ┌──────────┐ ┌──────────┐
        │  Providers  │ │   Core   │ │  Models  │
        │  (DO/AWS)   │ │ (SSH/Log)│ │(Instance)│
        └─────────────┘ └──────────┘ └──────────┘
```

### Module Responsibilities

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (cli.py)                        │
│  - App configuration (cyclopts)                             │
│  - Command registration                                      │
│  - Help text and argument parsing                           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Commands (commands/)                      │
│                                                             │
│  instance.py        │ Instance lifecycle commands           │
│  nginx_cmd.py       │ Nginx configuration commands          │
│  nuxt_cmd.py        │ Nuxt deployment commands              │
│  fastapi_cmd.py     │ FastAPI deployment commands           │
│                                                             │
│  Responsibilities:                                          │
│  - Thin wrappers around business logic                      │
│  - Argument validation                                       │
│  - Error handling and user feedback                         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   Applications (apps/)                       │
│                                                             │
│  base.py            │ Base deployment patterns              │
│  nuxt.py            │ Nuxt-specific deployment              │
│  fastapi.py         │ FastAPI-specific deployment           │
│                                                             │
│  Responsibilities:                                          │
│  - App sync and build logic                                 │
│  - Change detection (source hashing)                        │
│  - Process management (PM2, supervisor)                     │
│  - Service restart/status/logs                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     Network (network/)                       │
│                                                             │
│  validation.py      │ IP/DNS/HTTP validation                │
│  dns.py             │ DNS record management                 │
│  nginx.py           │ Nginx config & SSL setup              │
│                                                             │
│  Responsibilities:                                          │
│  - DNS propagation checks                                   │
│  - HTTP/HTTPS health checks                                 │
│  - Let's Encrypt certificate issuance                       │
│  - Nginx reverse proxy configuration                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      Server (server/)                        │
│                                                             │
│  setup.py           │ Bootstrap new servers                 │
│  firewall.py        │ UFW firewall management               │
│  verification.py    │ Health checks                         │
│                                                             │
│  Responsibilities:                                          │
│  - cloud-init, package installation                         │
│  - Swap file creation                                       │
│  - User/permission setup                                    │
│  - UFW port management                                      │
│  - End-to-end health verification                           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   Providers (providers/)                     │
│                                                             │
│  base.py            │ Provider Protocol (interface)         │
│  digitalocean.py    │ DigitalOcean implementation           │
│  aws.py             │ AWS implementation                    │
│  factory.py         │ Provider factory function             │
│                                                             │
│  Responsibilities:                                          │
│  - Instance create/delete/list                              │
│  - DNS record management                                    │
│  - SSH key upload                                           │
│  - Cloud-specific auth validation                           │
│  - Resource cleanup (security groups, etc)                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      Core (core/)                            │
│                                                             │
│  logging.py         │ Colored output (log/warn/error)       │
│  shell.py           │ Local command execution               │
│  ssh.py             │ Remote execution (Fabric wrappers)    │
│                                                             │
│  Responsibilities:                                          │
│  - Subprocess management                                    │
│  - SSH/SFTP connections                                     │
│  - File transfer (rsync, tar+scp fallback)                  │
│  - Error handling and logging                               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     Models (models/)                         │
│                                                             │
│  instance.py        │ Instance data model & persistence     │
│  app.py             │ App data model & management           │
│                                                             │
│  Responsibilities:                                          │
│  - JSON serialization/deserialization                       │
│  - Instance state management (.instance.json)               │
│  - App tracking and conflict detection                      │
│  - Schema migration (old → new format)                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Flow Examples

### Example 1: Create Instance

```
User runs: deploy-vm instance create myapp --provider aws

  1. cli.py → commands/instance.py::create_instance()
  2. commands/instance.py:
     - Calls providers/factory.py::get_provider("aws")
     - Validates parameters
  3. providers/aws.py::AWSProvider.create_instance()
     - Creates EC2 instance
     - Returns {id, ip, ...}
  4. server/setup.py::setup_server()
     - Uses core/ssh.py to run commands
     - Installs packages, configures UFW
  5. models/instance.py::save_instance()
     - Writes myapp.instance.json

Result: myapp.instance.json created, server ready
```

### Example 2: Deploy Nuxt App

```
User runs: deploy-vm nuxt deploy myapp example.com /src you@ex.com

  1. cli.py → commands/nuxt_cmd.py::deploy_nuxt()
  2. commands/nuxt_cmd.py:
     - Loads instance: models/instance.py::load_instance("myapp")
     - Creates instance if doesn't exist
  3. apps/nuxt.py::NuxtDeployment.sync()
     - Computes source hash: apps/base.py::compute_source_hash()
     - Syncs files: core/ssh.py::rsync()
     - Builds app on server
     - Updates PM2 config
  4. network/dns.py::ensure_dns_matches()
     - Checks DNS: network/validation.py::resolve_dns_a()
     - Updates if needed: providers/aws.py::setup_dns()
  5. network/nginx.py::setup_nginx_ssl()
     - Generates config: network/nginx.py::generate_nginx_server_block()
     - Installs Let's Encrypt cert
     - Reloads nginx
  6. server/verification.py::verify_instance()
     - Checks SSH, DNS, HTTP, HTTPS
  7. models/app.py::add_app_to_instance()
     - Updates apps array in instance.json

Result: App deployed, DNS configured, HTTPS working
```

### Example 3: Restart FastAPI App

```
User runs: deploy-vm fastapi restart myapp

  1. cli.py → commands/fastapi_cmd.py::restart_supervisor()
  2. commands/fastapi_cmd.py:
     - Loads instance: models/instance.py::load_instance("myapp")
     - Detects SSH user: apps/base.py::get_ssh_user()
  3. apps/fastapi.py::FastAPIDeployment.restart_service()
     - Selects app: apps/base.py::select_app("fastapi")
     - Runs supervisorctl restart via core/ssh.py::ssh()
  4. apps/fastapi.py::FastAPIDeployment.check_status()
     - Runs supervisorctl status
     - Displays output

Result: App restarted, status shown
```

---

## Testing Architecture

```
tests/
├── unit/                    # Fast, isolated tests (no I/O)
│   ├── test_logging.py      # Mock print()
│   ├── test_shell.py        # Mock subprocess
│   ├── test_instance.py     # Mock filesystem
│   ├── test_validation.py   # Mock DNS/HTTP
│   └── test_nginx.py        # Test config generation
│
├── integration/             # Medium, mock external services
│   ├── test_providers.py    # Mock doctl/boto3
│   ├── test_ssh.py          # Mock Fabric
│   └── test_deployment.py   # Mock end-to-end flow
│
└── e2e/                     # Slow, real cloud instances
    ├── test_nuxt_deploy.py  # Real DigitalOcean instance
    └── test_fastapi_deploy.py # Real AWS instance
```

**Test Coverage Goal:** 80%+

---

## Migration Phases

```
Phase 1: Foundation        Phase 2: Network         Phase 3: Providers
├── core/                  ├── network/             ├── providers/
├── models/                └── server/              └── (keep working)
└── (still works)          └── (still works)

Phase 4: Applications      Phase 5: Commands        Phase 6: Polish
├── apps/                  ├── commands/            ├── Tests
│   ├── base.py            │   ├── instance.py      ├── Documentation
│   ├── nuxt.py            │   ├── nginx_cmd.py     └── Cleanup
│   └── fastapi.py         │   ├── nuxt_cmd.py
└── (still works)          │   └── fastapi_cmd.py
                           └── cli.py
```

**Key Principle:** After each phase, all tests pass and CLI works

---

## Backwards Compatibility

### CLI Commands
✅ **No breaking changes** - all commands work identically:
```bash
# Before refactoring
deploy-vm instance create myapp

# After refactoring (identical)
deploy-vm instance create myapp
```

### Instance JSON Format
✅ **No breaking changes** - same `.instance.json` format:
```json
{
  "id": 543540359,
  "ip": "170.64.235.136",
  "provider": "digitalocean",
  "apps": [{"name": "myapp", "type": "nuxt", "port": 3000}]
}
```

### Python API
⚠️ **Minor breaking changes** for programmatic users:
```python
# Before: Import from single file
from deploy_vm import create_instance

# After: Import from package
from deploy_vm.commands.instance import create_instance
```

**Mitigation:** Keep top-level imports in `deploy_vm/__init__.py` for common functions

---

## Performance Considerations

### No Runtime Impact
- Module imports cached by Python
- Same function calls, just reorganized
- No additional abstraction layers

### Startup Time
- **Before:** Import single 2,332-line file (~50ms)
- **After:** Import package with 15 modules (~60ms)
- **Impact:** +10ms (negligible for CLI tool)

### Development Velocity
- **Before:** Edit 2,332-line file, run all tests (slow)
- **After:** Edit 150-line module, run relevant tests (fast)
- **Impact:** 3-5x faster iteration

---

## Risk Mitigation

### High-Risk Areas
1. **Provider implementations** - complex, external APIs
2. **App deployment** - orchestrates multiple components
3. **SSH operations** - network failures, timeouts

### Safety Measures
1. **Feature branch** - no direct commits to main
2. **Incremental migration** - each phase tested independently
3. **Keep original file** - `deploy_vm_legacy.py` as fallback
4. **Staging environment** - test before production
5. **Rollback plan** - revert commits if issues

---

## Success Metrics

### Code Quality
- [ ] Cyclomatic complexity < 10 per function
- [ ] Average function length < 50 lines
- [ ] No functions > 100 lines
- [ ] Test coverage > 80%

### Maintainability
- [ ] New provider added in < 4 hours
- [ ] New app type added in < 6 hours
- [ ] Bug fix localized to single module
- [ ] Documentation up-to-date

### Reliability
- [ ] All existing tests pass
- [ ] New unit tests pass
- [ ] Integration tests pass
- [ ] E2E tests pass on real instances
