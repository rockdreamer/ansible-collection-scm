#!/usr/bin/env python3

# TODO:
# - database:
# - DB_TYPE option marks an alternative
# - ";; Other settings" in description marks settings that are common
# - Add asserts based on list of valid values
# - Add custom asserts

import re
import subprocess
import sys

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from textwrap import dedent


class ConfigType(Enum):
    STRING = "string"
    BOOLEAN = "boolean"
    LIST = "list"


@dataclass
class Option:
    """
    Represents an option in the configuration file.
    """

    name: str
    default_value: str
    after_comment: str
    description: list[str]
    deprecated_comment: str
    valid_values: list[str] = None


@dataclass
class Section:
    """
    Represents a section in the configuration file.
    """

    name: str
    options: list[Option]
    description: list[str]


"""
Option names that are used in the role but have different names in the Forgejo configuration.
"""
CUSTOM_OPTION_NAMES = {
    "app_name": "forgejo_name",
    "app_slogan": "forgejo_slogan",
    "app_display_name_format": "forgejo_display_name_format",
    "run_user": "forgejo_system_user",
    "run_mode": "forgejo_run_mode",
    "work_path": "forgejo_working_dir",
    "forgejo_attachment.minio_endpoint": "forgejo_attachment.minio.endpoint",
    "forgejo_attachment.minio_access_key_id": "forgejo_attachment.minio.access_key_id",
    "forgejo_attachment.minio_secret_access_key": "forgejo_attachment.minio.secret_access_key",
    "forgejo_attachment.minio_bucket": "forgejo_attachment.minio.bucket",
    "forgejo_attachment.minio_location": "forgejo_attachment.minio.location",
    "forgejo_attachment.minio_base_path": "forgejo_attachment.minio.base_path",
    "forgejo_attachment.minio_use_ssl": "forgejo_attachment.minio.use_ssl",
    "forgejo_attachment.minio_insecure_skip_verify": "forgejo_attachment.minio.insecure_skip_verify",
    "forgejo_attachment.minio_checksum_algorithm": "forgejo_attachment.minio.checksum_algorithm",
    "forgejo_attachment.minio_bucket_lookup": "forgejo_attachment.minio.bucket_lookup",
    "forgejo_security.reverse_proxy_authentication_user": "forgejo_security.reverse_proxy.authentication.user",
    "forgejo_security.reverse_proxy_authentication_email": "forgejo_security.reverse_proxy.authentication.email",
    "forgejo_security.reverse_proxy_authentication_full_name": "forgejo_security.reverse_proxy.authentication.full_name",
    "forgejo_security.reverse_proxy_authentication_limit": "forgejo_security.reverse_proxy.authentication.limit",
    "forgejo_security.reverse_proxy_authentication_trusted_proxies": "forgejo_security.reverse_proxy.authentication.trusted_proxies",
    "forgejo_security.only_allow_push_if_gitea_environment_set": "forgejo_security.only_allow_push_if_forgejo_environment_set",
}

"""
Constraints for valid values of options.
"""
VALID_OPTION_VALUES = {
    "forgejo_admin.default_email_notifications": ["enabled", "onmention", "disabled"],
    "forgejo_admin.user_disabled_features": [
        "deletion",
        "manage_ssh_keys",
        "manage_gpg_keys",
    ],
    "forgejo_attachment.minio.checksum_algorithm": ["default", "md5"],
    "forgejo_attachment.storage_type": ["local", "minio"],
    "forgejo_cache.adapter": ["memory", "redis", "memcache", "twoqueue"],
    "forgejo_database.db_type": [
        "mysql",
        "postgres",
        "sqlite3",
    ],  # msssql is not supported by forgejo anymore
    "forgejo_database.ssl_mode": [
        "false",
        "true",
        "skip-verify",
        "disable",
        "require",
        "verify-full",
    ],
    "forgejo_indexer.issue_indexer_type": [
        "bleve",
        "db",
        "elasticsearch",
        "meilisearch",
    ],
    "forgejo_indexer.repo_indexer_type": ["bleve", "elasticsearch"],
    "forgejo_log.level": [
        "trace",
        "debug",
        "info",
        "warn",
        "error",
        "critical",
        "none",
    ],
    "forgejo_log.mode": ["console", "file", "conn", "smtp", "database"],
    "forgejo_mailer.protocol": [
        "smtp",
        "smtps",
        "smtp+starttls",
        "smtp+unix",
        "sendmail",
        "dummy",
    ],
    "forgejo_oauth2_client.account_linking": ["disabled", "login", "auto"],
    "forgejo_oauth2_client.username": ["userid", "nickname", "email"],
    "forgejo_oauth2.jwt_signing_algorithm": [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    ],
    "forgejo_picture.repository_avatar_fallback": ["none", "random", "image"],
    "forgejo_repository.default_private": ["last", "private", "public"],
    "forgejo_repository.signing.crud_actions": [
        "never",
        "pubkey",
        "twofa",
        "always",
        "parentsigned",
    ],
    "forgejo_repository.signing.default_trust_model": [
        "collaborator",
        "committer",
        "collaboratorcommitter",
    ],
    "forgejo_repository.signing.initial_commit": ["never", "pubkey", "twofa", "always"],
    "forgejo_repository.signing.merges": [
        "never",
        "pubkey",
        "twofa",
        "always",
        "basesigned",
        "commitssigned",
        "approved",
    ],
    "forgejo_repository.signing.wiki": ["never", "pubkey", "twofa", "always"],
    "forgejo_security.password_complexity": ["lower", "upper", "digit", "spec"],
    "forgejo_security.password_hash_algo": ["argon2", "pbkdf2", "scrypt", "bcrypt"],
    "forgejo_server.protocol": ["http", "https", "http+unix", "fcgi", "fcgi+unix"],
    "forgejo_server.ssh_authorized_principals_allow": [
        "empty",
        "off",
        "email",
        "username",
        "anything",
    ],
    "forgejo_server.landing_page": ["home", "explore", "organizations", "login"],
    "forgejo_service.captcha_type": [
        "image",
        "recaptcha",
        "hcaptcha",
        "mcaptcha",
        "cfturnstile",
    ],
    "forgejo_service.default_user_visibility": ["public", "limited", "private"],
    "forgejo_service.default_org_visibility": ["public", "limited", "private"],
    "forgejo_session.provider": [
        "memory",
        "file",
        "redis",
        "db",
        "mysql",
        "couchbase",
        "memcache",
        "postgres",
    ],
    "forgejo_session.same_site": ["none", "lax", "strict"],
    "forgejo_run_mode": ["test", "dev", "prod"],
}

CUSTOM_ASSERTS = [
    # forgejo_attachment.path only if forgejo_attachment.storage_type == "local"
    # forgejo_attachment.serve_direct only if forgejo_attachment.storage_type == "minio" and
    # forgejo_cache.host only if forgejo_cache.adapter in ["redis", "memcache", "twoqueue"]
    # forgejo_cache.interval only if forgejo_cache.adapter == "memory"
    # forgejo_camo.enabled only if forgejo_camo.server_url and forgejo_camo.hmac_key are set
    # forgejo_database.charset only if forgejo_database.db_type == "mysql"
    # forgejo_database.passwd only if forgejo_database.db_type in ["mysql", "postgres"]
    # forgejo_database.path only if forgejo_database.db_type == "sqlite3"
    # forgejo_database.schema only if forgejo_database.db_type == "postgres"
    # forgejo_database.sqlite_journal_mode only if forgejo_database.db_type == "sqlite3"
    # forgejo_database.sqlite_timeout  only if forgejo_database.db_type == "sqlite3"
    # forgejo_database.ssl_mode only if forgejo_database.db_type in ["mysql", "postgres"]
    # forgejo_indexer.issue_indexer_path only if forgejo_indexer.issue_indexer_type == "bleve"
    # forgejo_indexer.issue_indexer_conn_str only if forgejo_indexer.issue_indexer_type in ["elasticsearch", "meilisearch"]
    # forgejo_indexer.issue_indexer_name only if forgejo_indexer.issue_indexer_type in ["elasticsearch", "meilisearch"]
    # forgejo_indexer.repo_indexer_path only if forgejo_indexer.repo_indexer_type == "bleve"
    # forgejo_indexer.repo_indexer_conn_str only if forgejo_indexer.issue_indexer_type in ["elasticsearch"]
    # forgejo_indexer.repo_indexer_name only if forgejo_indexer.issue_indexer_type in ["elasticsearch"]
    # forgejo_oauth2.jwt_signing_private_key_file only if forgejo_oauth2.jwt_signing_algorithm in ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
    # forgejo_oauth2.jwt_secret only if forgejo_oauth2.jwt_signing_algorithm in ["HS256", "HS384", "HS512"]
]

UNMARKED_LIST_OPTIONS = [
    "forgejo_admin.external_user_disable_features",
    "forgejo_admin.user_disabled_features",
    "forgejo_cors.allow_domain",
    "forgejo_cors.headers",
    "forgejo_cors.x_frame_options",
    "forgejo_indexer.repo_indexer_exclude",
    "forgejo_indexer.repo_indexer_include",
    "forgejo_log.mode",
    "forgejo_markdown.custom_url_schemes",
    "forgejo_migrations.allowed_domains",
    "forgejo_migrations.blocked_domains",
    "forgejo_openid.blacklisted_uris",
    "forgejo_openid.whitelisted_uris",
    "forgejo_proxy.proxy_hosts",
    "forgejo_repository.disabled_repo_units",
    "forgejo_repository.release.allowed_types",
    "forgejo_repository.signing.crud_actions",
    "forgejo_repository.signing.initial_commit",
    "forgejo_repository.signing.wiki",
    "forgejo_security.password_complexity",
    "forgejo_server.ssh_trusted_user_ca_keys",
    "forgejo_server.ssl_cipher_suites",
    "forgejo_service.email_domain_allowlist",
    "forgejo_service.email_domain_blocklist",
    "forgejo_service.email_domain_whitelist",
    "forgejo_webhook.allowed_host_list",
    "forgejo_webhook.proxy_hosts",
]

NOT_REALLY_LISTS = [
    "forgejo_ui.meta.description",
]

WHITESPACE_SEPARATED_LIST_OPTIONS = [
    "forgejo_openid.whitelisted_uris",
    "forgejo_openid.blacklisted_uris",
]

# These are either undocumented in the ini file or deprecated
WEIRD_OPTIONS = {
    "cors": [
        Option(
            name="ALLOW_SUBDOMAIN",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Not documented",
        ),
    ],
    "indexer": [
        Option(
            name="ISSUE_INDEXER_QUEUE_TYPE",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="use settings in `[queue.issue_indexer]",
        ),
        Option(
            name="ISSUE_INDEXER_QUEUE_TYPE",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="use settings in `[queue.issue_indexer]",
        ),
        Option(
            name="ISSUE_INDEXER_QUEUE_DIR",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="use settings in `[queue.issue_indexer]",
        ),
        Option(
            name="ISSUE_INDEXER_QUEUE_CONN_STR",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="use settings in `[queue.issue_indexer]",
        ),
        Option(
            name="ISSUE_INDEXER_QUEUE_BATCH_NUMBER",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="use settings in `[queue.issue_indexer]",
        ),
        Option(
            name="UPDATE_BUFFER_LEN",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="use settings in `[queue.issue_indexer]",
        ),
    ],
    "lfs": [
        Option(
            name="MINIO_ENDPOINT",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_lfs.storage_type to a storage name like my_minio and use `storage.my_minio.minio_endpoint` instead",
        ),
        Option(
            name="MINIO_ACCESS_KEY_ID",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_lfs.storage_type to a storage name like my_minio and use `storage.my_minio.minio_access_key_id` instead",
        ),
        Option(
            name="MINIO_SECRET_ACCESS_KEY",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_lfs.storage_type to a storage name like my_minio and use `storage.my_minio.minio_secret_access_key` instead",
        ),
        Option(
            name="MINIO_BUCKET",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_lfs.storage_type to a storage name like my_minio and use `storage.my_minio.minio_bucket` instead",
        ),
        Option(
            name="MINIO_LOCATION",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_lfs.storage_type to a storage name like my_minio and use `storage.my_minio.minio_location` instead",
        ),
        Option(
            name="MINIO_USE_SSL",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_lfs.storage_type to a storage name like my_minio and use `storage.my_minio.minio_use_ssl` instead",
        ),
        Option(
            name="MINIO_INSECURE_SKIP_VERIFY",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_lfs.storage_type to a storage name like my_minio and use `storage.my_minio.minio_insecure_skip_verify` instead",
        ),
        Option(
            name="MINIO_CHECKSUM_ALGORITHM",
            default_value="default",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_lfs.storage_type to a storage name like my_minio and use `storage.my_minio.minio_checksum_algorithm` instead",
        ),
    ],
    "log": [
        Option(
            name="DISABLE_ROUTER_LOG",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Use 'forgejo_log.logger.router.mode = none' instead",
        ),
        Option(
            name="ROUTER",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Use 'forgejo_log.logger.router.mode = none' instead",
        ),
        Option(
            name="ENABLE_ACCESS_LOG",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Use 'logger.access.MODE=,' instead",
        ),
        Option(
            name="ACCESS",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Use 'logger.access.MODE' instead",
        ),
    ],
    "log.console": [
        Option(
            name="COLORIZE",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="",
        ),
    ],
    "mirror": [
        Option(
            name="MIRROR_QUEUE_LENGTH",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Use 'queue.mirror.length' instead",
        ),
        Option(
            name="PULL_REQUEST_QUEUE_LENGTH",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Use 'queue.pr_patch_checker.length' instead",
        ),
    ],
    "other": [
        Option(
            name="SHOW_FOOTER_BRANDING",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Use 'forgejo_other.show_footer_powered_by' instead",
        ),
    ],
    "packages": [
        Option(
            name="MINIO_ENDPOINT",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_packages.storage_type to a storage name like my_minio and use `storage.my_minio.minio_endpoint` instead",
        ),
        Option(
            name="MINIO_ACCESS_KEY_ID",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_packages.storage_type to a storage name like my_minio and use `storage.my_minio.minio_access_key_id` instead",
        ),
        Option(
            name="MINIO_SECRET_ACCESS_KEY",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_packages.storage_type to a storage name like my_minio and use `storage.my_minio.minio_secret_access_key` instead",
        ),
        Option(
            name="MINIO_BUCKET",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_packages.storage_type to a storage name like my_minio and use `storage.my_minio.minio_bucket` instead",
        ),
        Option(
            name="MINIO_LOCATION",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_packages.storage_type to a storage name like my_minio and use `storage.my_minio.minio_location` instead",
        ),
        Option(
            name="MINIO_USE_SSL",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_packages.storage_type to a storage name like my_minio and use `storage.my_minio.minio_use_ssl` instead",
        ),
        Option(
            name="MINIO_INSECURE_SKIP_VERIFY",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_packages.storage_type to a storage name like my_minio and use `storage.my_minio.minio_insecure_skip_verify` instead",
        ),
        Option(
            name="MINIO_CHECKSUM_ALGORITHM",
            default_value="default",
            description=[""],
            after_comment="",
            deprecated_comment="Set forgejo_packages.storage_type to a storage name like my_minio and use `storage.my_minio.minio_checksum_algorithm` instead",
        ),
    ],
    "picture": [
        Option(
            name="AVATAR_UPLOAD_PATH",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="",
        ),
        Option(
            name="REPOSITORY_AVATAR_UPLOAD_PATH",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="",
        ),
    ],
    "repository.pull-request": [
        Option(
            name="TEST_CONFLICTING_PATCHES_WITH_GIT_APPLY",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Not used",
        ),
    ],
    "security": [
        Option(
            name="COOKIE_USERNAME",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="This is no longer used.",
        ),
    ],
    "server": [
        Option(
            name="DISABLE_ROUTER_LOG",
            default_value="false",
            description=[""],
            after_comment="",
            deprecated_comment="Use 'forgejo_log.logger.router.mode = none' instead",
        ),
    ],
    "service": [
        Option(
            name="EMAIL_DOMAIN_WHITELIST",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="Use 'forgejo_service.email_domain_allowlist' instead",
        ),
    ],
    "time": [
        Option(
            name="FORMAT",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="This is no longer used.",
        ),
    ],
    "ui": [
        Option(
            name="THEME_COLOR_META_TAG",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="This is no longer used.",
        ),
        Option(
            name="USE_SERVICE_WORKER",
            default_value="",
            description=[""],
            after_comment="",
            deprecated_comment="This is no longer used.",
        ),
    ],
}

DEPRECATED_SECTIONS = [
    Section(
        name="task",
        options=[
            Option(
                name="QUEUE_TYPE",
                default_value="",
                after_comment="",
                description=[],
                deprecated_comment="Use 'forgejo_queue.task.type' instead",
            ),
            Option(
                name="QUEUE_LENGTH",
                default_value="",
                description=[],
                after_comment="",
                deprecated_comment="Use 'forgejo_queue.task.length' instead",
            ),
            Option(
                name="QUEUE_CONN_STR",
                default_value="",
                description=[],
                after_comment="",
                deprecated_comment="Use 'forgejo_queue.task.conn_str' instead",
            ),
        ],
        description=[
            "Deprecated section for task queue configuration.",
            "Use 'forgejo_queue.task' instead.",
        ],
    ),
    Section(
        name="git.reflog",
        options=[
            Option(
                name="ENABLED",
                default_value="false",
                after_comment="",
                description=[],
                deprecated_comment="Use 'git.config.gc.reflogExpire' instead",
            ),
            Option(
                name="EXPIRATION",
                default_value="",
                description=[],
                after_comment="",
                deprecated_comment="Use 'git.config.gc.reflogExpire' instead",
            ),
        ],
        description=[
            "Deprecated section for setting up git.",
            "Use 'git.config' instead.",
        ],
    ),
    Section(
        name="log.smtp",
        options=[
            Option(
                name="SMTP",
                default_value="false",
                after_comment="",
                description=[],
                deprecated_comment="The SMTP logger was removed",
            ),
        ],
        description=[
            "Deprecated section. The SMTP logger was removed in 1.20.1.",
        ],
    ),
]

CUSTOM_SECTION_HANDLING = {
    "git.config": "forgejo.custom.d/gitconfig.j2",
    "highlight.mapping": "forgejo.custom.d/highlight.j2",
    "log.%(WriterMode)": "forgejo.custom.d/log_writermode.j2",
    "mailer.override_header": "forgejo.custom.d/mailer_override_header.j2",
    "markup.asciidoc": "forgejo.custom.d/markup_custom.j2",
    "markup.sanitizer.1": "forgejo.custom.d/markup_sanitizer.j2",
    "repository.mimetype_mapping": "forgejo.custom.d/repository_mimetype_mapping.j2",
    "storage.my_minio": "forgejo.custom.d/storage_custom.j2",
}


# INI file printing functions
def print_option_in_ini(option: Option, out):
    for line in option.description:
        out.write(f";; {line}\n")
    if option.deprecated_comment:
        out.write(f";; Deprecated: {option.deprecated_comment}\n")
    if option.after_comment:
        out.write(f"{option.name} = {option.default_value} ; {option.after_comment}\n")
    else:
        out.write(f"{option.name} = {option.default_value}\n")


def print_section_in_ini(section: Section, out):
    for line in section.description:
        out.write(f";; {line}\n")
    if section.name:
        out.write(
            "\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n"
        )
        out.write(f"[{section.name}]\n")
        out.write(
            ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n;;\n"
        )
    out.write("\n")
    for option in section.options:
        print_option_in_ini(option, out)


# Ansible template printing functions
def section_needs_enable_set(section: Section) -> Option | None:
    """
    Checks if the section has an 'enabled' option that must be set to true.
    Some sections like cron are default-enabled and we want to explicitly write
    that they are being disabled.
    """
    if section.name.lower().startswith("cron"):
        return None
    for name in ["enabled", "proxy_enabled"]:
        for option in section.options:
            if option.name.lower() == name and option.default_value == "false":
                return option
    return None


def ansible_section_variable(section: Section) -> str:
    return "forgejo_" + section.name.lower().replace("-", "_")


def dotted_option_name(section: Section, option: Option) -> str:
    """
    Returns the dotted name of the option, e.g. "section.option_name".
    """
    option_name = (
        f"forgejo_{section.name}.{option.name}" if section.name else option.name
    )
    option_name = option_name.lower().replace("-", "_")
    option_name = CUSTOM_OPTION_NAMES.get(option_name, option_name)
    return option_name


def option_type(section: Section, option: Option) -> ConfigType:
    """
    Determines the type of the configuration option based on its default value.
    """
    if option.default_value.lower() in ["true", "false"]:
        return ConfigType.BOOLEAN
    elif dotted_option_name(section, option) in UNMARKED_LIST_OPTIONS or (
        "," in option.default_value
        and not dotted_option_name(section, option) in NOT_REALLY_LISTS
    ):
        return ConfigType.LIST
    else:
        return ConfigType.STRING


def template_file(section: Section, templates_directory: Path) -> Path:
    """
    Returns the template name where options for the section are generated in the role.
    """
    if not section.name:
        return templates_directory / "forgejo.ini.j2"
    return templates_directory / "forgejo.d" / (section.name.split(".")[0] + ".j2")


def print_option_in_template(section: Section, option: Option, out):
    if option.deprecated_comment:
        out.write(f"\n;; {option.name} is deprecated: {option.deprecated_comment}\n")
    if option_type(section, option) == ConfigType.STRING:
        out.write(
            dedent(
                f"""
                {{% if {dotted_option_name(section, option)} | default('') | string | length > 0 %}}
                {option.name} = {{{{ {dotted_option_name(section, option)} }}}}
                {{% endif %}}
                """
            )
        )
    elif option_type(section, option) == ConfigType.BOOLEAN:
        out.write(
            dedent(
                f"""
                {{% if {dotted_option_name(section, option)} | default('') | string | length > 0 %}}
                {option.name} = {{{{ {dotted_option_name(section, option)} | bodsch.core.config_bool(true_as='true', false_as='false') }}}}
                {{% endif %}}
                """
            )
        )
    elif option_type(section, option) == ConfigType.LIST:
        separator = (
            " "
            if dotted_option_name(section, option) in WHITESPACE_SEPARATED_LIST_OPTIONS
            else ", "
        )
        out.write(
            dedent(
                f"""
                {{% if { dotted_option_name(section, option) } is defined and
                { dotted_option_name(section, option) } | count > 0 %}}
                {option.name} = {{{{ {dotted_option_name(section, option) } | join('{ separator }') }}}}
                {{% endif %}}
                """
            )
        )
    else:
        raise ValueError(
            f"Unsupported config type for option {option.name} in section {section.name}"
        )


def print_main_template(sections: list[Section], git_id, out):
    main_section = sections[0]
    out.write("#jinja2: trim_blocks: True, lstrip_blocks: True\n")
    out.write(";; {{ ansible_managed }}\n")
    out.write(";; Ansible jinja template forgejo.ini.j2 generated from forgejo's\n")
    out.write(
        f";; custom/conf/app.example.ini git id {git_id} by update_from_default_ini.py\n\n"
    )

    print_section_variables_in_template(main_section, out)

    included = set()
    included.add(template_file(main_section, Path()))

    remaining_sections = sections[1:]
    # Previous versions of the role sorted the sections by name.
    # This is not necessary and by keeping the order in the original default
    # forgejo ini file, a user can do manual checks, but if you want to keep
    # the order, you can uncomment the following lines and replace the for loop.
    # remaining_sections = sorted(
    #     sections[1:], key=lambda s: s.name.lower()
    # )  # Sort remaining sections by name
    for section in remaining_sections:
        section_filename = template_file(section, Path())
        if section.name in CUSTOM_SECTION_HANDLING:
            out.write(
                f"\n\n{{# Section {section.name} is custom-handled #}}\n{{% include('{ CUSTOM_SECTION_HANDLING[section.name] }') %}}\n\n"
            )
        elif section_filename not in included:
            included.add(section_filename)
            out.write(f"{{% include('{ section_filename }') %}}\n")
    out.write(
        "\n\n{# Adding custom handling of queues #}\n{% include('forgejo.custom.d/queue_custom.j2') %}\n\n"
    )


def print_section_variables_in_template(section: Section, out):
    if section.name in CUSTOM_SECTION_HANDLING:
        out.write(
            f"\n\n{{# Section {section.name} is custom-handled in { CUSTOM_SECTION_HANDLING[section.name] } #}}\n\n"
        )
        return
    if section.name:
        if enabled_option := section_needs_enable_set(section):
            out.write(
                dedent(
                    f"""
                    {{% if { ansible_section_variable(section) } is defined and { ansible_section_variable(section) } | count > 0 and
                        { ansible_section_variable(section) }.{enabled_option.name.lower()} | default('{enabled_option.default_value}') | bool %}}
                    """
                )
            )
        else:
            out.write(
                dedent(
                    f"""
                    {{% if { ansible_section_variable(section) } is defined and
                        { ansible_section_variable(section) } | count > 0 %}}
                    """
                )
            )
        out.write(f"\n[{section.name}]\n\n")
    printed = set()
    for option in section.options:
        if option.name not in printed:
            print_option_in_template(section, option, out)
            printed.add(option.name)
    if section.name:
        out.write("{% endif %}")


def clear_template_files(sections, templates_directory: Path) -> Path:
    for section in sections:
        template_file(section, templates_directory).unlink(missing_ok=True)


def update_templates(templates_directory: Path, sections: list[Section], git_id: str):
    clear_template_files(sections, templates_directory)
    main_section = sections[0]
    main_template_path = template_file(main_section, templates_directory)
    with open(main_template_path, "w") as out:
        print_main_template(sections, git_id, out)
    opened = set()
    for section in sections[1:]:
        f = template_file(section, templates_directory)
        with open(f, "a") as out:
            if f not in opened:
                out.write(
                    f";; Ansible jinja template {f.name} generated from /custom/conf/app.default.ini\n;; git id {git_id} by update_from_default_ini.py\n"
                )
                opened.add(f)
            print_section_variables_in_template(section, out)


def read_section_descriptions(default_ini_path: Path) -> list[Section]:
    """
    Reads the default.ini file and returns a list of Sections describing what options are available.
    """
    sections = []

    section_regex = re.compile(r"^;?\s*\[(?P<section_name>.+)\]\s*$")
    option_regex = re.compile(
        r"^;{0,2}\s*(?P<option_name>[A-Z0-9_]+|logger\.[a-z]*\.MODE)\s*=\s*(?P<default_value>[^;]*);?(?P<comment>.*)$"
    )
    description_regex = re.compile(r"^;;?\s*(?P<description>.*)$")

    with open(default_ini_path, "r") as f:
        current_section = Section(name="", description=["General settings"], options=[])
        current_comment = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            if section_match := section_regex.match(line):
                # If we encounter a new section, save the current one and start a new one
                for weird_option in WEIRD_OPTIONS.get(current_section.name, []):
                    current_section.options.append(weird_option)
                sections.append(current_section)
                current_section = Section(
                    name=section_match.group("section_name"),
                    description=current_comment,
                    options=[],
                )
                current_comment = []
            elif option_match := option_regex.match(line):
                # If we encounter an option, add it to the current section
                option_name = option_match.group("option_name")
                default_value = option_match.group("default_value").strip()
                comment = option_match.group("comment").strip()
                current_section.options.append(
                    Option(
                        name=option_name,
                        description=current_comment,
                        after_comment=comment,
                        default_value=default_value,
                        deprecated_comment="",
                    )
                )
                current_comment = []
            elif description_match := description_regex.match(line):
                current_comment.append(description_match.group("description"))
    sections.extend(DEPRECATED_SECTIONS)
    return sections


def get_git_id(default_ini_path: Path) -> str:
    try:
        return (
            subprocess.check_output(
                ["git", "describe", "--exclude", "*-test", "--tags", "--always"],
                cwd=default_ini_path.parent,
                text=True,
            )
            .strip()
            .removeprefix("v")
            .replace("-g", "-", count=1)
        )
    except subprocess.CalledProcessError:
        return "unknown"


def main():
    current_script_path = Path(__file__).resolve()
    parent_directory = current_script_path.parent
    templates_directory = parent_directory / "templates" / "conf"

    if len(sys.argv) < 3:
        print(
            "Usage: python update_from_default_ini.py <command> <path to custom/conf/app.example.ini>\n"
            "Commands:\n"
            "  print_sections: Print the names of the sections\n"
            "  print_options: Print the names of the sections and their options\n"
            "  print_ini: Print the sections and options in INI format (for comparing with the original)\n"
            "  update_templates: Update the template files\n"
        )
        sys.exit(1)

    # If an argument is provided, use it as the path to the default.ini file
    command = sys.argv[1]
    default_ini_path = Path(sys.argv[2])
    if not default_ini_path.is_file():
        print(f"Error: The file {default_ini_path} does not exist.")
        sys.exit(1)
    git_id = get_git_id(default_ini_path)
    sections = read_section_descriptions(default_ini_path)

    if command == "print_sections":
        # Print the names of the sections
        for section in sections:
            print(section.name)

    elif command == "print_options":
        # Print the names of the sections
        for section in sections:
            for option in section.options:
                if option.deprecated_comment:
                    print(
                        f"{section.name}.{option.name} = {option.default_value} ; {option.deprecated_comment}"
                    )
                else:
                    print(f"{section.name}.{option.name} = {option.default_value}")

    elif command == "print_ini":
        print(
            f";; Generated from {default_ini_path} git id {git_id} by update_from_default_ini.py"
        )
        for section in sections:
            print_section_in_ini(section, sys.stdout)

    elif command == "update_templates":
        update_templates(templates_directory, sections, git_id)


if __name__ == "__main__":
    main()
