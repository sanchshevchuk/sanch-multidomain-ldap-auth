<?php
/**
 * Plugin Name:       Active Directory Multi-Domain Auth & ACL
 * Description:       Ultimate Enterprise AD Integration: Zero-Trust ACL, Smart Tree Routing, Loop/Search Leak Protection, LDAP Clone Guard, and Role Cap Merge.
 * Version:           1.0.0
 * Author:            sanchshevchuk
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       active-directory-multi-domain-auth-acl
 * Requires at least: 5.8
 * Requires PHP:      7.4
 */

if (!defined('ABSPATH')) exit;

// ============================================================================
// 0. DRY HELPER: AUTONOMOUS CUSTOM ROLE GENERATOR (WITH CAP MERGE)
// ============================================================================
function ad_auth_sync_role($slug, $base, $force_update = false) {
    if (!empty($slug) && !in_array($slug, ['administrator', 'editor', 'author', 'contributor', 'subscriber'])) {
        $base_role = get_role($base);
        $base_caps = $base_role ? $base_role->capabilities : ['read' => true];
        
        $existing_role = get_role($slug);
        
        // SEC-GUARD: Type check before calling add_cap to prevent Fatal Error if role is broken
        if ($existing_role && is_a($existing_role, 'WP_Role') && $force_update) {
            foreach ($base_caps as $cap => $grant) {
                $existing_role->add_cap($cap, $grant);
            }
        } elseif (!$existing_role) {
            add_role($slug, $slug, $base_caps);
        }
    }
}

add_action('init', 'ad_auth_self_heal_roles', 1);

function ad_auth_self_heal_roles() {
    if (!is_admin() && get_transient('ad_auth_roles_healed')) return;

    $options = get_option('ad_auth_settings', []);
    if (!empty($options['role_mapping']) && is_array($options['role_mapping'])) {
        foreach ($options['role_mapping'] as $row) {
            $slug = is_array($row) ? trim($row['wp_slug'] ?? '') : trim($row);
            $base = is_array($row) ? trim($row['wp_base'] ?? 'subscriber') : 'subscriber';
            ad_auth_sync_role($slug, $base, false);
        }
    }
    set_transient('ad_auth_roles_healed', 1, 86400);
}

// ============================================================================
// 1. AUTHENTICATION CORE & ZERO-TRUST AD SYNCHRONIZATION
// ============================================================================
add_filter('authenticate', 'ad_multidomain_authenticate', 30, 3);

function ad_multidomain_authenticate($user, $username, $password) {
    if (empty($username) || empty($password) || is_a($user, 'WP_User')) {
        return $user;
    }

    if (!function_exists('ldap_connect')) {
        error_log("[AD Auth Critical] LDAP extension missing. Check PHP configuration.");
        return new WP_Error('ad_auth_no_ldap', __('<b>Server Error:</b> LDAP extension is not installed.', 'ad-multidomain-auth'));
    }

    $options = get_option('ad_auth_settings', []);
    
    $ad_servers = !empty($options['servers']) ? $options['servers'] : [
        ['ip' => '', 'enc' => 'starttls', 'domain' => '', 'base_dn' => '']
    ];

    $role_mapping    = !empty($options['role_mapping']) ? $options['role_mapping'] : [['ad_group' => 'Domain_Admins', 'wp_slug' => 'administrator', 'wp_base' => 'administrator', 'url_path' => '']];
    $enforce_ad_role = !empty($options['enforce_ad_role']) ? (int)$options['enforce_ad_role'] : 1;

    $target_domain = '';
    if (strpos($username, '@') !== false) {
        $parts          = explode('@', $username);
        $clean_username = $parts[0];
        $target_domain  = strtolower(trim($parts[1]));
    } else {
        $clean_username = $username;
    }

    // SEC-GUARD: Proper LDAP escape fallback
    $safe_username = function_exists('ldap_escape') 
        ? ldap_escape($clean_username, '', LDAP_ESCAPE_FILTER) 
        : str_replace(['\\', '*', '(', ')', "\x00"], ['\\5c', '\\2a', '\\28', '\\29', '\\00'], $clean_username);

    $auth_success = false;
    $ad_data = [
        'email'      => '',
        'first_name' => '',
        'last_name'  => '',
        'role'       => null,
        'domain'     => '',
        'groups'     => []
    ];

    foreach ($ad_servers as $server) {
        if (empty($server['ip']) || empty($server['domain'])) continue;

        if (!empty($target_domain) && strtolower(trim($server['domain'])) !== $target_domain) {
            continue;
        }

        $enc = !empty($server['enc']) ? $server['enc'] : 'plain';
        if (empty($server['enc'])) {
            if (!empty($server['use_tls'])) $enc = 'starttls';
            elseif (!empty($server['proto']) && $server['proto'] === 'ldaps://') $enc = 'ldaps';
            elseif (!empty($server['port']) && $server['port'] == 636) $enc = 'ldaps';
        }

        $ip_input = trim($server['ip']);
        $ip_input = str_replace(['ldap://', 'ldaps://'], '', $ip_input);
        
        if (strpos($ip_input, ':') !== false) {
            $parts = explode(':', $ip_input);
            $ip_clean = trim($parts[0]);
            $port     = (int)$parts[1];
        } else {
            $ip_clean = $ip_input;
            $port     = ($enc === 'ldaps') ? 636 : 389;
            if (!empty($server['port'])) $port = (int)$server['port'];
        }

        $proto   = ($enc === 'ldaps') ? 'ldaps://' : 'ldap://';
        $host    = $proto . $ip_clean;
        $use_tls = ($enc === 'starttls');

        $ldap_conn = @ldap_connect($host, $port);
        if (!$ldap_conn) {
            error_log("[AD Auth Error] Connection failed to {$host}:{$port}");
            continue;
        }

        @ldap_set_option($ldap_conn, LDAP_OPT_NETWORK_TIMEOUT, 2);
        @ldap_set_option($ldap_conn, LDAP_OPT_TIMELIMIT, 2);
        @ldap_set_option($ldap_conn, LDAP_OPT_TIMEOUT, 2);
        @ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        @ldap_set_option($ldap_conn, LDAP_OPT_REFERRALS, 0);

        if ($use_tls) {
            if (!@ldap_start_tls($ldap_conn)) {
                error_log("[AD Auth Error] StartTLS failed on {$ip_clean}: " . ldap_error($ldap_conn));
                @ldap_unbind($ldap_conn);
                continue;
            }
        } elseif ($enc === 'plain') {
            error_log("[AD Auth Warning] Using unencrypted LDAP (Plaintext) for user {$clean_username} on {$ip_clean}.");
        }

        $upn  = $clean_username . '@' . $server['domain'];
        $bind = @ldap_bind($ldap_conn, $upn, $password);

        if ($bind) {
            $auth_success = true;
            $ad_data['domain'] = $server['domain'];
            $ad_data['email']  = $clean_username . '@' . $server['domain'];

            $current_base_dn = trim($server['base_dn'] ?? '');
            if (empty($current_base_dn)) {
                $current_base_dn = 'DC=' . str_replace('.', ',DC=', trim($server['domain']));
            }

            $filter     = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName={$safe_username}))";
            $attributes = ['givenName', 'sn', 'mail', 'memberOf', 'memberOf:1.2.840.113556.1.4.1941:', 'accountExpires'];
            
            $search = @ldap_search($ldap_conn, $current_base_dn, $filter, $attributes);
            
            if ($search) {
                $count = @ldap_count_entries($ldap_conn, $search);
                
                // SEC-GUARD: Prevent LDAP Cloning Privilege Escalation
                if ($count > 1) {
                    error_log("[AD Auth Critical] Multiple records found for {$clean_username} on {$ip_clean}. Authentication aborted to prevent privilege escalation.");
                    @ldap_unbind($ldap_conn);
                    return new WP_Error('ad_auth_multiple', __('<b>Access Denied:</b> Multiple AD accounts match this username. Contact administrator to refine Base DN.', 'ad-multidomain-auth'));
                }

                if ($count === 1) {
                    $entry = @ldap_first_entry($ldap_conn, $search);
                    if ($entry) {
                        $attrs = @ldap_get_attributes($ldap_conn, $entry);

                        if (!empty($attrs['accountExpires'][0])) {
                            $expires = (int)$attrs['accountExpires'][0];
                            if ($expires > 0 && $expires < 9223372036854775807) {
                                $unix_expires = ($expires / 10000000) - 11644473600;
                                if (time() > $unix_expires) {
                                    @ldap_unbind($ldap_conn);
                                    return new WP_Error('ad_auth_expired', __('<b>Access Denied:</b> Your Active Directory account has expired.', 'ad-multidomain-auth'));
                                }
                            }
                        }

                        $ad_data['first_name'] = $attrs['givenName'][0] ?? '';
                        $ad_data['last_name']  = $attrs['sn'][0] ?? '';
                        if (!empty($attrs['mail'][0])) {
                            $ad_data['email'] = $attrs['mail'][0];
                        }

                        $raw_groups = [];
                        if (!empty($attrs['memberOf:1.2.840.113556.1.4.1941:'])) {
                            $raw_groups = (array)$attrs['memberOf:1.2.840.113556.1.4.1941:'];
                        } elseif (!empty($attrs['memberOf'])) {
                            $raw_groups = (array)$attrs['memberOf'];
                        }
                        unset($raw_groups['count']);

                        foreach ($raw_groups as $g_dn) {
                            if (is_string($g_dn) && preg_match('/^CN=([^,]+)/i', $g_dn, $matches)) {
                                $ad_data['groups'][] = strtolower(trim($matches[1]));
                            }
                        }

                        foreach ($role_mapping as $row) {
                            $group_cn = is_array($row) ? ($row['ad_group'] ?? '') : $row;
                            $role     = is_array($row) ? ($row['wp_slug'] ?? '') : $row;
                            if (empty($group_cn) || empty($role)) continue;
                            
                            $pattern = '/^CN=' . preg_quote(trim($group_cn), '/') . '(,|$)/i';
                            foreach ($raw_groups as $group_dn) {
                                if (is_string($group_dn) && preg_match($pattern, $group_dn)) {
                                    $ad_data['role'] = $role;
                                    break 2;
                                }
                            }
                        }
                    }
                }
            } else {
                error_log("[AD Auth Error] Account {$clean_username} not found on {$ip_clean}. Used Base DN: {$current_base_dn}");
            }

            @ldap_unbind($ldap_conn);
            break; 
        } else {
            if (ldap_errno($ldap_conn) === 49) {
                $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
                error_log("[AD Auth Audit] ❌ Failed login attempt (Invalid password): {$upn} from IP {$client_ip}");
            } else {
                error_log("[AD Auth Error] Bind failed on {$ip_clean} ({$upn}): " . ldap_error($ldap_conn));
            }
        }

        @ldap_unbind($ldap_conn);
    }

    if (!$auth_success) {
        return new WP_Error('ad_auth_failed', __('<b>Login Error:</b> Invalid domain username or password.', 'ad-multidomain-auth'));
    }

    if (empty($ad_data['role'])) {
        return new WP_Error('ad_auth_denied', __('<b>Access Denied:</b> Your AD account does not belong to any allowed intranet groups.', 'ad-multidomain-auth'));
    }

    $scoped_username = $clean_username . '@' . strtolower($ad_data['domain']);
    $wp_username     = sanitize_user($scoped_username, true);
    
    $wp_user = get_user_by('login', $wp_username);

    $is_new_user = false;
    $real_email  = null;
    if (!$wp_user) {
        if (email_exists($ad_data['email'])) {
            $real_email = $ad_data['email'];
            $ad_data['email'] = $clean_username . '+' . strtolower($ad_data['domain']) . '@no-reply.local';
            error_log("[AD Auth Notice] Email conflict for {$wp_username}. Fallback email assigned.");
        }
        
        $user_id = wp_create_user($wp_username, wp_generate_password(24), $ad_data['email']);
        if (is_wp_error($user_id)) {
            error_log("[AD Auth Error] Failed to create WP account {$wp_username}: " . $user_id->get_error_message());
            return $user_id;
        }
        $is_new_user = true;
        $wp_user = new WP_User($user_id);
        if (!empty($real_email)) {
            update_user_meta($wp_user->ID, '_ad_real_email', $real_email);
        }
    }

    update_user_meta($wp_user->ID, '_ad_user_groups', $ad_data['groups']);

    $needs_update = false;
    $update_data  = ['ID' => $wp_user->ID];

    if ($wp_user->user_email !== $ad_data['email'] && !email_exists($ad_data['email'])) {
        $update_data['user_email'] = $ad_data['email'];
        $needs_update = true;
    }
    
    $display_name = trim($ad_data['first_name'] . ' ' . $ad_data['last_name']) ?: $clean_username;
    if ($wp_user->display_name !== $display_name) {
        $update_data['display_name'] = $display_name;
        $needs_update = true;
    }

    if ($wp_user->first_name !== $ad_data['first_name'] || $wp_user->last_name !== $ad_data['last_name'] || $needs_update) {
        if ($needs_update) wp_update_user($update_data);
        update_user_meta($wp_user->ID, 'first_name', $ad_data['first_name']);
        update_user_meta($wp_user->ID, 'last_name', $ad_data['last_name']);
        clean_user_cache($wp_user->ID);
    }

    if ($enforce_ad_role || $is_new_user || empty($wp_user->roles)) {
        if (!in_array($ad_data['role'], (array)$wp_user->roles)) {
            $wp_user->set_role($ad_data['role']);
        }
    }

    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    error_log("[AD Auth Audit] ✅ Successful login: User {$wp_username} ({$ad_data['email']}) from IP {$client_ip}");

    return new WP_User($wp_user->ID);
}

// ============================================================================
// 2. STRICT WHITELIST, SMART TREE, IN-MEMORY CACHE & REST/WRITE ACL
// ============================================================================
add_action('template_redirect', 'ad_auth_access_control');
add_filter('rest_authentication_errors', 'ad_auth_rest_access_control');
add_action('do_feed', 'ad_auth_block_feeds', 1);
add_filter('map_meta_cap', 'ad_auth_enforce_write_acl', 10, 4);
add_filter('wp_nav_menu_objects', 'ad_auth_filter_nav_menu_objects', 10, 2);
add_filter('get_pages', 'ad_auth_filter_pages', 10, 2);

add_filter('the_posts', 'ad_auth_filter_loop_posts', 10, 2);

function ad_auth_filter_loop_posts($posts, $query) {
    if (is_admin() || !is_user_logged_in() || empty($posts)) {
        return $posts;
    }
    
    $filtered_posts = [];
    foreach ($posts as $post) {
        $post_id = is_object($post) ? $post->ID : (is_numeric($post) ? (int)$post : 0);
        
        if (!$post_id) {
            $filtered_posts[] = $post;
            continue;
        }

        if (ad_auth_user_can_access_url(get_permalink($post_id))) {
            $filtered_posts[] = $post;
        }
    }
    return $filtered_posts;
}

add_action('rest_api_init', function() {
    foreach (get_post_types(['show_in_rest' => true], 'names') as $post_type) {
        add_filter("rest_prepare_{$post_type}", 'ad_auth_rest_filter_content_acl', 10, 3);
    }
});

function ad_auth_rest_filter_content_acl($response, $post, $request) {
    if (current_user_can('manage_options')) return $response;
    
    $url = get_permalink($post->ID);
    if (!ad_auth_user_can_access_url($url)) {
        return new WP_Error('rest_forbidden_acl', __('403 Forbidden: Content access restricted by AD ACL.', 'ad-multidomain-auth'), ['status' => 403]);
    }
    return $response;
}

function ad_auth_enforce_write_acl($caps, $cap, $user_id, $args) {
    $write_caps = [
        'edit_post', 'delete_post', 'publish_posts',
        'edit_page', 'delete_page', 'publish_pages',
        'edit_others_posts', 'edit_others_pages'
    ];

    if (in_array($cap, $write_caps) && !empty($args[0])) {
        $post = get_post($args[0]);
        if ($post && !user_can($user_id, 'manage_options')) {
            $url = get_permalink($post->ID);
            if ($url && !ad_auth_user_can_access_url($url)) {
                $caps[] = 'do_not_allow';
            }
        }
    }
    return $caps;
}

function ad_auth_user_can_access_url($url) {
    static $url_cache = [];
    if (isset($url_cache[$url])) return $url_cache[$url];

    $current_user = wp_get_current_user();
    if (!$current_user->exists()) return ($url_cache[$url] = false);

    $user_roles = (array) $current_user->roles;
    if (in_array('administrator', $user_roles)) return ($url_cache[$url] = true);

    static $role_mapping = null;
    if ($role_mapping === null) {
        $options      = get_option('ad_auth_settings', []);
        $role_mapping = !empty($options['role_mapping']) ? $options['role_mapping'] : [];
    }
    
    $req_path = strtolower(rawurldecode(parse_url($url, PHP_URL_PATH) ?? ''));
    if (empty($req_path) || $req_path === '/') return ($url_cache[$url] = true);

    static $user_ad_groups_cache = [];
    if (!isset($user_ad_groups_cache[$current_user->ID])) {
        $user_ad_groups_cache[$current_user->ID] = array_map('strtolower', (array) get_user_meta($current_user->ID, '_ad_user_groups', true));
    }
    $user_ad_groups = $user_ad_groups_cache[$current_user->ID];
    
    static $user_roles_lower_cache = [];
    if (!isset($user_roles_lower_cache[$current_user->ID])) {
        $user_roles_lower_cache[$current_user->ID] = array_map('strtolower', $user_roles);
    }
    $user_roles_lower = $user_roles_lower_cache[$current_user->ID];
    
    $matched_any_rule = false;
    $has_access       = false;

    foreach ($role_mapping as $rule) {
        if (!is_array($rule)) continue;
        $rule_path  = trim($rule['url_path'] ?? '');
        $rule_group = strtolower(trim($rule['ad_group'] ?? ''));
        $rule_role  = strtolower(trim($rule['wp_slug'] ?? ''));
        if (empty($rule_path)) continue;

        $paths = array_map('trim', explode(',', strtolower(rawurldecode($rule_path))));
        foreach ($paths as $p) {
            if (empty($p)) continue;
            $protected_path = rtrim($p, '/') . '/';
            $current_path   = rtrim($req_path, '/') . '/';

            if (strpos($current_path, $protected_path) === 0) {
                $matched_any_rule = true;
                if (in_array($rule_group, $user_ad_groups) || in_array($rule_role, $user_roles_lower)) {
                    $has_access = true;
                }
            }
        }
    }

    if (!$matched_any_rule) return ($url_cache[$url] = false);

    return ($url_cache[$url] = $has_access);
}

function ad_auth_access_control() {
    if (is_admin() || wp_doing_ajax() || wp_is_json_request() || (defined('REST_REQUEST') && REST_REQUEST) || defined('DOING_CRON') || strpos($_SERVER['REQUEST_URI'], '/wp-login.php') !== false) {
        return;
    }

    if (!is_user_logged_in()) {
        auth_redirect();
        exit;
    }

    $clean_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '/';
    if (!ad_auth_user_can_access_url($clean_uri)) {
        wp_die(
            '<div style="max-width:600px; margin:50px auto; font-family:sans-serif; text-align:center; padding:30px; border:1px solid #ddd; border-radius:8px; background:#fff;">' .
            '<h1 style="color:#d63638; margin-top:0;">' . esc_html__('403 Forbidden', 'ad-multidomain-auth') . '</h1>' .
            '<p style="font-size:16px; color:#555;">' . esc_html__('Your account does not have permission to view this intranet section.', 'ad-multidomain-auth') . '</p>' .
            '<p style="margin-top:25px;"><a href="' . esc_url(home_url()) . '" style="background:#2271b1; color:#fff; text-decoration:none; padding:10px 20px; border-radius:4px; font-weight:bold;">' . esc_html__('Return to Home', 'ad-multidomain-auth') . '</a></p>' .
            '</div>',
            esc_html__('Access Denied', 'ad-multidomain-auth'),
            ['response' => 403]
        );
    }
}

function ad_auth_filter_nav_menu_objects($sorted_menu_items, $args) {
    if (is_admin() || !is_user_logged_in()) {
        return $sorted_menu_items;
    }

    $denied_ids = [];
    $parent_map = [];

    foreach ($sorted_menu_items as $item) {
        $parent_map[$item->ID] = $item->menu_item_parent;
        if (!empty($item->url) && !ad_auth_user_can_access_url($item->url)) {
            $denied_ids[$item->ID] = true;
        }
    }

    $filtered_items = [];
    foreach ($sorted_menu_items as $item) {
        if (isset($denied_ids[$item->ID])) continue;

        $is_denied = false;
        $current_parent = $item->menu_item_parent;
        
        while ($current_parent) {
            if (isset($denied_ids[$current_parent])) {
                $is_denied = true;
                $denied_ids[$item->ID] = true;
                break;
            }
            $current_parent = isset($parent_map[$current_parent]) ? $parent_map[$current_parent] : 0;
        }

        if (!$is_denied) {
            $filtered_items[] = $item;
        }
    }

    return $filtered_items;
}

function ad_auth_filter_pages($pages, $r) {
    if (is_admin() || !is_user_logged_in()) {
        return $pages;
    }

    $filtered_pages = [];
    static $permalink_cache = [];

    foreach ($pages as $page) {
        if (!isset($permalink_cache[$page->ID])) {
            $permalink_cache[$page->ID] = get_permalink($page->ID);
        }
        if (ad_auth_user_can_access_url($permalink_cache[$page->ID])) {
            $filtered_pages[] = $page;
        }
    }
    return $filtered_pages;
}

function ad_auth_rest_access_control($result) {
    if (!empty($result)) return $result;
    
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if (!is_user_logged_in() && strpos($uri, '/wp-json/') !== false) {
        return new WP_Error('rest_forbidden', __('REST API access is restricted for guests.', 'ad-multidomain-auth'), ['status' => 401]);
    }
    
    if (is_user_logged_in() && !current_user_can('manage_options') && strpos($uri, '/wp-json/wp/v2/users') !== false) {
        return new WP_Error('rest_forbidden_users', __('403 Forbidden: User enumeration is disabled.', 'ad-multidomain-auth'), ['status' => 403]);
    }
    
    return $result;
}

function ad_auth_block_feeds() {
    if (!is_user_logged_in()) {
        wp_die(esc_html__('RSS feeds are disabled for the intranet portal.', 'ad-multidomain-auth'), esc_html__('Access Denied', 'ad-multidomain-auth'), ['response' => 403]);
    }
}

// ============================================================================
// 3. ADMIN SETTINGS UI
// ============================================================================
add_action('admin_menu', 'ad_auth_add_admin_menu');

function ad_auth_add_admin_menu() {
    add_options_page(
        __('AD Multi-Domain Auth & ACL', 'ad-multidomain-auth'), 
        __('AD Auth Settings', 'ad-multidomain-auth'), 
        'manage_options', 
        'ad_multi_auth', 
        'ad_auth_options_page'
    );
}

function ad_auth_options_page() {
    if (!current_user_can('manage_options')) return;

    $dropped_rows = 0;

    if (isset($_POST['ad_auth_submit'])) {
        check_admin_referer('ad_auth_save');
        
        $old_options = get_option('ad_auth_settings', []);
        $old_mapping = !empty($old_options['role_mapping']) ? $old_options['role_mapping'] : [];
        $old_roles   = [];
        foreach ($old_mapping as $om) {
            if (is_array($om) && !empty($om['wp_slug'])) $old_roles[] = $om['wp_slug'];
        }
        $new_roles_slugs = [];
        
        $new_options = [
            'enforce_ad_role' => isset($_POST['enforce_ad_role']) ? 1 : 0,
            'servers'         => [],
            'role_mapping'    => []
        ];

        // WP-REPO: Use wp_unslash on $_POST array variables
        if (!empty($_POST['servers_ip']) && is_array($_POST['servers_ip'])) {
            $post_ips = wp_unslash($_POST['servers_ip']);
            $post_encs = wp_unslash($_POST['servers_enc'] ?? []);
            $post_domains = wp_unslash($_POST['servers_domain'] ?? []);
            $post_bases = wp_unslash($_POST['servers_base_dn'] ?? []);

            foreach ($post_ips as $i => $ip) {
                $ip_clean = trim(sanitize_text_field($ip));
                if (empty($ip_clean)) continue;
                $new_options['servers'][] = [
                    'ip'      => $ip_clean,
                    'enc'     => sanitize_text_field($post_encs[$i] ?? 'plain'),
                    'domain'  => trim(sanitize_text_field($post_domains[$i] ?? '')),
                    'base_dn' => trim(sanitize_text_field($post_bases[$i] ?? ''))
                ];
            }
        }

        if (!empty($_POST['map_ad_group']) && is_array($_POST['map_ad_group'])) {
            $post_groups = wp_unslash($_POST['map_ad_group']);
            $post_slugs = wp_unslash($_POST['map_wp_slug'] ?? []);
            $post_slugs_custom = wp_unslash($_POST['map_wp_slug_custom'] ?? []);
            $post_bases = wp_unslash($_POST['map_wp_base'] ?? []);
            $post_paths = wp_unslash($_POST['map_url_path'] ?? []);

            foreach ($post_groups as $i => $ad_group) {
                $group_clean = trim(sanitize_text_field($ad_group));
                $slug_clean  = trim(sanitize_key($post_slugs[$i] ?? ''));
                if ($slug_clean === '_custom_') {
                    $slug_clean = trim(sanitize_key($post_slugs_custom[$i] ?? ''));
                }
                
                $base_clean  = trim(sanitize_key($post_bases[$i] ?? 'subscriber'));
                $path_clean  = trim(sanitize_text_field($post_paths[$i] ?? ''));

                if (!empty($group_clean) && !empty($slug_clean)) {
                    $new_options['role_mapping'][] = [
                        'ad_group' => $group_clean,
                        'wp_slug'  => $slug_clean,
                        'wp_base'  => $base_clean,
                        'url_path' => $path_clean
                    ];
                    $new_roles_slugs[] = $slug_clean;

                    ad_auth_sync_role($slug_clean, $base_clean, true);
                } elseif (!empty($group_clean) || !empty($post_slugs_custom[$i])) {
                    $dropped_rows++;
                }
            }
        }

        foreach ($old_roles as $old_slug) {
            if (!in_array($old_slug, $new_roles_slugs) && !in_array($old_slug, ['administrator', 'editor', 'author', 'contributor', 'subscriber'])) {
                remove_role($old_slug);
            }
        }

        delete_transient('ad_auth_roles_healed');
        update_option('ad_auth_settings', $new_options);
        
        echo '<div class="updated"><p><strong>' . esc_html__('Settings successfully saved.', 'ad-multidomain-auth') . '</strong></p></div>';
        if ($dropped_rows > 0) {
            echo '<div class="notice notice-warning is-dismissible"><p><strong>' . esc_html__('Warning:', 'ad-multidomain-auth') . '</strong> ' . sprintf(esc_html__('%d incomplete rule(s) were dropped (missing AD group or empty custom role ID).', 'ad-multidomain-auth'), intval($dropped_rows)) . '</p></div>';
        }
    }

    $options  = get_option('ad_auth_settings', []);
    $servers  = !empty($options['servers']) ? array_filter($options['servers']) : [['ip' => '', 'enc' => 'starttls', 'domain' => '', 'base_dn' => '']];
    $raw_mapping = !empty($options['role_mapping']) ? $options['role_mapping'] : [['ad_group' => 'Domain_Admins', 'wp_slug' => 'administrator', 'wp_base' => 'administrator', 'url_path' => '']];
    
    $mapping = [];
    foreach ($raw_mapping as $k => $v) {
        if (is_array($v)) {
            $mapping[] = $v;
        } else {
            $mapping[] = ['ad_group' => $k, 'wp_slug' => $v, 'wp_base' => 'subscriber', 'url_path' => ''];
        }
    }

    $enforce_ad_role = isset($options['enforce_ad_role']) ? (int)$options['enforce_ad_role'] : 1;
    
    $wp_roles = wp_roles()->get_names();
    
    $site_pages = get_pages(['sort_column' => 'post_title', 'hierarchical' => 1]);
    $site_cats  = get_terms(['taxonomy' => 'category', 'hide_empty' => false]);
    
    $sections_options_html = '<option value="">' . esc_html__('➕ Append path from site catalog...', 'ad-multidomain-auth') . '</option>';
    foreach ($site_pages as $p) {
        $path = rawurldecode(parse_url(get_permalink($p->ID), PHP_URL_PATH));
        $sections_options_html .= '<option value="' . esc_attr($path) . '">' . esc_html__('📄 Page:', 'ad-multidomain-auth') . ' ' . esc_html(trim($p->post_title)) . ' (' . esc_html($path) . ')</option>';
    }
    if (!is_wp_error($site_cats) && !empty($site_cats)) {
        foreach ($site_cats as $c) {
            $path = rawurldecode(parse_url(get_term_link($c), PHP_URL_PATH));
            $sections_options_html .= '<option value="' . esc_attr($path) . '">' . esc_html__('📁 Category:', 'ad-multidomain-auth') . ' ' . esc_html(trim($c->name)) . ' (' . esc_html($path) . ')</option>';
        }
    }
    
    $tls_warning = false;
    foreach ($servers as $s) { 
        if (empty($s['ip'])) continue;
        $enc = !empty($s['enc']) ? $s['enc'] : 'plain';
        if (empty($s['enc'])) {
             if (!empty($s['use_tls'])) $enc = 'starttls';
             elseif (!empty($s['proto']) && $s['proto'] === 'ldaps://') $enc = 'ldaps';
             elseif (!empty($s['port']) && $s['port'] == 636) $enc = 'ldaps';
        }
        if ($enc === 'plain') {
            $tls_warning = true;
            break;
        }
    }
    ?>
    <div class="wrap">
        <h1><?php esc_html_e('Active Directory Multi-Domain & ACL Settings', 'ad-multidomain-auth'); ?></h1>
        
        <?php if ($tls_warning): ?>
        <div class="notice notice-warning is-dismissible">
            <p><strong><?php esc_html_e('Security Warning:', 'ad-multidomain-auth'); ?></strong> <?php esc_html_e('Found domain controllers with disabled encryption. Authentication transmits passwords in plaintext.', 'ad-multidomain-auth'); ?></p>
        </div>
        <?php endif; ?>

        <form method="post" action="">
            <?php wp_nonce_field('ad_auth_save'); ?>
            
            <h2><?php esc_html_e('1. Domain Controllers (DC)', 'ad-multidomain-auth'); ?></h2>
            <table class="widefat fixed" id="servers-table" style="margin-bottom: 10px;">
                <thead>
                    <tr>
                        <th style="width: 22%;"><?php esc_html_e('Protocol & Encryption', 'ad-multidomain-auth'); ?></th>
                        <th style="width: 20%;"><?php esc_html_e('IP Address (or IP:Port)', 'ad-multidomain-auth'); ?></th>
                        <th style="width: 22%;"><?php esc_html_e('Domain (UPN Suffix)', 'ad-multidomain-auth'); ?></th>
                        <th style="width: 31%;"><?php esc_html_e('Base DN', 'ad-multidomain-auth'); ?> <span style="font-weight:normal; color:#666;">(<?php esc_html_e('Leave empty for auto-generation', 'ad-multidomain-auth'); ?>)</span></th>
                        <th style="width: 5%;"></th>
                    </tr>
                </thead>
                <tbody id="servers-body">
                    <?php foreach ($servers as $srv): 
                        $enc = 'plain';
                        if (!empty($srv['enc'])) {
                            $enc = $srv['enc'];
                        } else {
                            if (!empty($srv['use_tls'])) $enc = 'starttls';
                            elseif (!empty($srv['proto']) && $srv['proto'] === 'ldaps://') $enc = 'ldaps';
                            elseif (!empty($srv['port']) && $srv['port'] == 636) $enc = 'ldaps';
                        }
                    ?>
                    <tr>
                        <td>
                            <select name="servers_enc[]" class="widefat">
                                <option value="plain" <?php selected($enc, 'plain'); ?>><?php esc_html_e('LDAP (Plaintext, 389)', 'ad-multidomain-auth'); ?></option>
                                <option value="starttls" <?php selected($enc, 'starttls'); ?>><?php esc_html_e('LDAP + StartTLS (Encrypted, 389)', 'ad-multidomain-auth'); ?></option>
                                <option value="ldaps" <?php selected($enc, 'ldaps'); ?>><?php esc_html_e('LDAPS (SSL Tunnel, 636)', 'ad-multidomain-auth'); ?></option>
                            </select>
                        </td>
                        <td><input type="text" name="servers_ip[]" value="<?php echo esc_attr(str_replace(['ldap://', 'ldaps://'], '', $srv['ip'] ?? '')); ?>" class="widefat" placeholder="<?php esc_attr_e('e.g. 10.0.0.1 or 10.0.0.1:389', 'ad-multidomain-auth'); ?>" /></td>
                        <td><input type="text" name="servers_domain[]" value="<?php echo esc_attr($srv['domain'] ?? ''); ?>" class="widefat" placeholder="<?php esc_attr_e('e.g. corp.company.com', 'ad-multidomain-auth'); ?>" /></td>
                        <td><input type="text" name="servers_base_dn[]" value="<?php echo esc_attr($srv['base_dn'] ?? ''); ?>" class="widefat" placeholder="<?php esc_attr_e('Leave empty for auto-generation', 'ad-multidomain-auth'); ?>" /></td>
                        <td><button type="button" class="button remove-row">×</button></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <button type="button" class="button button-secondary" id="add-server"><?php esc_html_e('+ Add Server', 'ad-multidomain-auth'); ?></button>

            <h2 style="margin-top: 30px;"><?php esc_html_e('2. AD Groups Mapping, Roles & ACL Rules (Zero-Trust Mode)', 'ad-multidomain-auth'); ?></h2>
            <p class="description"><?php esc_html_e('If a user does not belong to any mapped AD group, access is denied. REST API and write permissions are protected by the same routing paths.', 'ad-multidomain-auth'); ?><br>
            <?php esc_html_e('Select a target URL path from the dropdown to automatically append it (comma-separated list).', 'ad-multidomain-auth'); ?></p>

            <table class="widefat fixed" id="mapping-table" style="max-width: 1050px; margin-bottom: 10px;">
                <thead>
                    <tr>
                        <th style="width: 22%;"><?php esc_html_e('AD Group Name (CN)', 'ad-multidomain-auth'); ?></th>
                        <th style="width: 22%;"><?php esc_html_e('WP Role Code (ID / Slug)', 'ad-multidomain-auth'); ?></th>
                        <th style="width: 16%;"><?php esc_html_e('Capabilities (Base Role)', 'ad-multidomain-auth'); ?></th>
                        <th style="width: 35%;"><?php esc_html_e('Allowed URL Path (Comma separated)', 'ad-multidomain-auth'); ?></th>
                        <th style="width: 5%;"></th>
                    </tr>
                </thead>
                <tbody id="mapping-body">
                    <?php foreach ($mapping as $row): 
                        if (empty($row['ad_group']) || empty($row['wp_slug'])) continue;
                    ?>
                    <tr>
                        <td style="vertical-align:top;">
                            <input type="text" name="map_ad_group[]" value="<?php echo esc_attr($row['ad_group']); ?>" class="widefat" placeholder="<?php esc_attr_e('e.g. Domain_Admins', 'ad-multidomain-auth'); ?>" style="margin-top:2px;" />
                        </td>
                        <td style="vertical-align:top;">
                            <select name="map_wp_slug[]" class="widefat wp-role-select" style="margin-top:2px;" onchange="if(this.value==='_custom_'){ this.nextElementSibling.style.display='block'; this.nextElementSibling.focus(); } else { this.nextElementSibling.style.display='none'; }">
                                <?php 
                                $current_slug = $row['wp_slug'];
                                $is_known = array_key_exists($current_slug, $wp_roles);
                                foreach ($wp_roles as $r_slug => $r_name): 
                                ?>
                                    <option value="<?php echo esc_attr($r_slug); ?>" <?php selected($current_slug, $r_slug); ?>><?php echo esc_html($r_slug); ?></option>
                                <?php endforeach; ?>
                                <?php if (!$is_known && !empty($current_slug)): ?>
                                    <option value="<?php echo esc_attr($current_slug); ?>" selected><?php echo esc_html($current_slug); ?></option>
                                <?php endif; ?>
                                <option value="_custom_"><?php esc_html_e('➕ Enter Custom ID...', 'ad-multidomain-auth'); ?></option>
                            </select>
                            <input type="text" name="map_wp_slug_custom[]" class="widefat custom-role-input" style="display:none; margin-top:5px;" placeholder="<?php esc_attr_e('e.g. operator_kyiv', 'ad-multidomain-auth'); ?>" />
                        </td>
                        <td style="vertical-align:top;">
                            <select name="map_wp_base[]" class="widefat" style="margin-top:2px;">
                                <option value="subscriber" <?php selected($row['wp_base'] ?? 'subscriber', 'subscriber'); ?>><?php esc_html_e('Subscriber (Read Only)', 'ad-multidomain-auth'); ?></option>
                                <option value="editor" <?php selected($row['wp_base'] ?? 'subscriber', 'editor'); ?>><?php esc_html_e('Editor (Content Mgmt)', 'ad-multidomain-auth'); ?></option>
                                <option value="author" <?php selected($row['wp_base'] ?? 'subscriber', 'author'); ?>><?php esc_html_e('Author (Own Posts)', 'ad-multidomain-auth'); ?></option>
                                <option value="administrator" <?php selected($row['wp_base'] ?? 'subscriber', 'administrator'); ?>><?php esc_html_e('Administrator', 'ad-multidomain-auth'); ?></option>
                            </select>
                        </td>
                        <td style="vertical-align:top;">
                            <input type="text" name="map_url_path[]" value="<?php echo esc_attr(rawurldecode($row['url_path'] ?? '')); ?>" class="widefat url-path-input" placeholder="<?php esc_attr_e('/sections/kyiv/, /docs/', 'ad-multidomain-auth'); ?>" style="margin-top:2px;" />
                            <select class="widefat url-path-helper" style="margin-top:4px; font-size:12px; color:#2271b1; border-color:#2271b1;" onchange="if(this.value){ var inp = this.parentNode.querySelector('.url-path-input'); var val = inp.value.trim().replace(/,$/, ''); inp.value = val ? val + ', ' + this.value : this.value; this.selectedIndex = 0; }">
                                <?php echo $sections_options_html; ?>
                            </select>
                        </td>
                        <td style="vertical-align:top;"><button type="button" class="button remove-row" style="margin-top:2px;">×</button></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <button type="button" class="button button-secondary" id="add-mapping"><?php esc_html_e('+ Add Rule', 'ad-multidomain-auth'); ?></button>

            <h2 style="margin-top: 30px;"><?php esc_html_e('3. Global Policy (SSOT)', 'ad-multidomain-auth'); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e('AD as Single Source of Truth:', 'ad-multidomain-auth'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="enforce_ad_role" value="1" <?php checked($enforce_ad_role, 1); ?> />
                            <strong><?php esc_html_e('Overwrite WordPress role on every login', 'ad-multidomain-auth'); ?></strong>
                        </label>
                        <p class="description"><?php esc_html_e('If enabled, manual WP role changes are discarded, and the role is synced from AD mapping every time a user logs in.', 'ad-multidomain-auth'); ?></p>
                    </td>
                </tr>
            </table>

            <p class="submit">
                <input type="submit" name="ad_auth_submit" id="submit" class="button button-primary" value="<?php esc_attr_e('Save Settings', 'ad-multidomain-auth'); ?>">
            </p>
        </form>
    </div>

    <script>
    document.addEventListener('DOMContentLoaded', function() {
        var strAuto = '<?php echo esc_js(__('Auto: ', 'ad-multidomain-auth')); ?>';
        var strLeave = '<?php echo esc_js(__('Leave empty for auto-generation', 'ad-multidomain-auth')); ?>';
        var strWarn = '<?php echo esc_js(__('Cannot remove the last row!', 'ad-multidomain-auth')); ?>';

        document.body.addEventListener('click', function(e) {
            if (e.target && e.target.classList.contains('remove-row')) {
                var row = e.target.closest('tr');
                if (row && row.parentNode.rows.length > 1) {
                    row.remove();
                } else {
                    alert(strWarn);
                }
            }
        });

        document.getElementById('add-server').addEventListener('click', function() {
            var tbody = document.getElementById('servers-body');
            var newRow = tbody.rows[0].cloneNode(true);
            newRow.querySelectorAll('input[type="text"]').forEach(input => input.value = '');
            newRow.querySelector('select[name="servers_enc[]"]').selectedIndex = 1; 
            
            var baseDnInput = newRow.querySelector('input[name="servers_base_dn[]"]');
            if(baseDnInput) baseDnInput.placeholder = strLeave;
            
            tbody.appendChild(newRow);
        });

        document.getElementById('add-mapping').addEventListener('click', function() {
            var tbody = document.getElementById('mapping-body');
            var newRow = tbody.rows[0].cloneNode(true);
            
            newRow.querySelectorAll('input[type="text"]:not(.custom-role-input)').forEach(input => input.value = '');
            
            var roleSelect = newRow.querySelector('.wp-role-select');
            var customInput = newRow.querySelector('.custom-role-input');
            
            if(roleSelect && customInput) {
                roleSelect.selectedIndex = 0;
                customInput.style.display = 'none';
                customInput.value = '';
            }
            
            newRow.querySelector('select[name="map_wp_base[]"]').selectedIndex = 0;
            
            var helperSelect = newRow.querySelector('.url-path-helper');
            if(helperSelect) helperSelect.selectedIndex = 0;
            
            tbody.appendChild(newRow);
        });

        document.addEventListener('input', function(e) {
            if (e.target && e.target.name === 'servers_domain[]') {
                var row = e.target.closest('tr');
                var baseDnInput = row.querySelector('input[name="servers_base_dn[]"]');
                var domainVal = e.target.value.trim();
                
                if (domainVal && baseDnInput) {
                    var autoDn = 'DC=' + domainVal.split('.').join(',DC=');
                    baseDnInput.placeholder = strAuto + autoDn;
                } else if (baseDnInput) {
                    baseDnInput.placeholder = strLeave;
                }
            }
        });

        document.querySelectorAll('input[name="servers_domain[]"]').forEach(function(inp) {
            inp.dispatchEvent(new Event('input', { bubbles: true }));
        });
    });
    </script>
    <?php
}
