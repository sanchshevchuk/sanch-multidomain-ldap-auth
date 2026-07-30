# Sanch MultiDomain LDAP Auth for Active Directory

[![WordPress Plugin Directory](https://img.shields.io/badge/WordPress.org-Awaiting_Review-blue.svg)](https://wordpress.org/plugins/sanch-multidomain-ldap-auth/)
[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D%207.4-777BB4.svg)](https://www.php.net/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

Enterprise-grade Active Directory multi-domain authentication, dynamic role mapping, and Zero-Trust ACL (Access Control List) system designed for WordPress intranet environments.

---

## Key Features

* **Multi-Domain & Multi-DC Support:** Connect multiple Active Directory Domain Controllers with automatic or custom Base DN routing.
* **Zero-Trust Access Control (ACL):** Restrict front-end pages, categories, and custom routes based on AD group memberships.
* **In-Memory Route Caching:** Static runtime caching for URL access validation, preventing database query bloat.
* **LDAP Clone Protection:** Detects duplicate user accounts across Base DNs to prevent potential privilege escalation.
* **Autonomous Custom Roles & Cap Merge:** Synchronizes AD groups with custom WordPress roles while merging third-party plugin capabilities.
* **REST API & Feed Shielding:** Protects REST API user enumeration endpoints and disables public RSS feeds for unauthorized users.
* **Secure Protocols:** Full support for LDAP + StartTLS (port 389) and LDAPS (SSL tunnel, port 636).

---

## Installation & Setup

1. Clone or download this repository into your `/wp-content/plugins/` directory:
   ```bash
   git clone [https://github.com/sanchshevchuk/sanch-multidomain-ldap-auth.git](https://github.com/sanchshevchuk/sanch-multidomain-ldap-auth.git)
Activate the plugin via WordPress Admin -> Plugins.

Navigate to Settings -> AD Auth Settings to configure your Domain Controllers and Group Mappings.

Security & Architecture
Input Sanitization & Escaping: Built adhering to strict WordPress Coding Standards (wp_unslash, strict nonces, IP validation/sanitization, and proper script enqueueing).

i18n Ready: Fully internationalized with native text domain support (sanch-multidomain-ldap-auth).

Single Source of Truth (SSOT): Option to overwrite WordPress user roles dynamically upon every successful AD login.

License
This project is licensed under the GPLv2 or later — see the LICENSE file for details.
