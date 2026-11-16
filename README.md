# Sanch MultiDomain LDAP Auth for Active Directory

[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D%207.4-777BB4.svg)](https://www.php.net/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

Enterprise-grade Active Directory multi-domain authentication, dynamic role mapping, and Zero-Trust ACL system for WordPress.

## Key Features

- **Multi-Domain & Multi-DC:** Connect multiple Active Directory Domain Controllers with automatic or custom Base DN routing.
- **Zero-Trust ACL:** Restrict front-end pages, categories, and custom routes by AD group memberships.
- **Security Hardening:** LDAP filter escaping, `LDAP_OPT_REFERRALS = 0`, clone protection across Base DNs, REST API & RSS shielding.
- **Dynamic Roles & Cap Merge:** Syncs AD groups with custom WordPress roles while preserving third-party plugin capabilities.
- **Protocols:** Supports LDAP + StartTLS (port `389`) and LDAPS (port `636`).

## Installation

1. Clone into `/wp-content/plugins/`:
   ```bash
   git clone https://github.com/sanchshevchuk/sanch-multidomain-ldap-auth.git
   ```
2. Activate the plugin in **WordPress Admin → Plugins**.
3. Configure Domain Controllers and Group Mappings under **Settings → AD Auth Settings**.

## License

GPLv2 or later — see [LICENSE](LICENSE).
