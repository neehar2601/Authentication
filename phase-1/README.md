# 🌾 FarmSight 360 — Keycloak Integrated Sample Application

A streamlined sample application modeled after **FarmSight 360**, integrated with a dedicated **Keycloak Realm (`farm360`)** and **PostgreSQL** database.

- **Users (Farmers & Service Providers)** sign in or self-register through the web application (`http://localhost:3000`) or via the Keycloak Hosted Login Page (`http://localhost:8080/realms/farm360/...`).
- **Administrators** manage users, reset login passwords, assign roles/groups, and enable/disable accounts directly through the official **Keycloak Admin Console Webpage** (`http://localhost:8080/admin/master/console/#/farm360/users`).

---

## 🚀 Quick Start (Docker Compose)

```bash
docker compose up -d --build
```

| Service | URL | Purpose |
|---|---|---|
| **FarmSight 360 Web App** | http://localhost:3000 | Login, Register, Farm & Crop Management, Workforce Attendance, Service Marketplace, Finances |
| **Flask Resource API** | http://localhost:5001/health | Validates Keycloak RS256 JWTs (`farm360` realm) & serves PostgreSQL data |
| **Keycloak Admin Webpage** | http://localhost:8080/admin/master/console/#/farm360/users | Official Keycloak Admin Console for user management, roles, groups & password resets |

---

## 🔐 Keycloak Realm & Pre-Seeded Accounts

On startup, the API automatically provisions the **`farm360`** realm in Keycloak with:
- **Realm**: `farm360` (Self-registration enabled, password reset enabled)
- **OIDC Public Client**: `farm360-web` (Standard Authorization Code Flow + Direct Access Grants enabled)
- **Realm Roles & Groups**:
  - `farmer` (`Farmers` group)
  - `service_provider` (`ServiceProviders` group)
  - `admin` (`Admins` group)

### Demo User Accounts (Realm: `farm360`)

| Username | Password | Role | Description |
|---|---|---|---|
| `ramesh` | `ramesh123` | `farmer` | Farm Owner — manages crop plots, worker attendance, finances, and books services |
| `kiran` | `kiran123` | `service_provider` | Agricultural Contractor — lists equipment/services and updates booking statuses |
| `admin_farm` | `admin123` | `admin` | Platform Administrator account in the `farm360` realm |

### 🛡️ Keycloak Master Admin Credentials (for `:8080/admin`)
- **URL**: http://localhost:8080/admin/master/console/#/farm360/users
- **Username**: `admin` (from `.env` `KC_ADMIN_USER`)
- **Password**: `Admin@2601` (from `.env` `KC_ADMIN_PASSWORD`)

---

## 🧩 Core FarmSight 360 Modules Included
1. **🔐 Authentication Gate**:
   - **Sign In**: Direct login against Keycloak `farm360` realm, 1-click Demo Login buttons (`ramesh` / `kiran`), or OIDC Redirect to Keycloak's Hosted Login Page.
   - **Register**: Self-service registration (`POST /api/register`) that creates the user in Keycloak's `farm360` realm, assigns their role & group (`farmer` or `service_provider`), and signs them in.
2. **🌾 Farms & Crops**: Add farm plots, track acreage, expected harvest yields (kg), and update crop growth stages (`Planted` → `Growing` → `Flowering` → `Ready for Harvest` → `Harvested`).
3. **👷 Workforce & Attendance**: Add farm workers and mark daily muster roll attendance (`Present`, `Half-Day`, `Absent`).
4. **🚜 Service Provider Marketplace & Bookings**: Browse and book contractor services (drone spraying, harvesters, soil testing), list new services, and update booking statuses (`Pending` → `Confirmed` → `Completed`).
5. **💰 Farm Finance Ledger**: Track farm income (harvest sales) and expenses (wages, inputs, completed service bookings).
