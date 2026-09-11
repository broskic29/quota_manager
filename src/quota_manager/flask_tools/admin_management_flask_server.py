from flask import (
    Flask,
    request,
    render_template_string,
    redirect,
    Response,
    url_for,
    session,
)
from sqlite3 import IntegrityError
import logging

import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm
import quota_manager.sqlite_helper_functions as sqlh
import quota_manager.flask_tools.flask_utils as flu
import quota_manager.quota_tools.smart_quota_tool as sqt

import quota_manager.flask_tools.admin_html as ahtml

from types import SimpleNamespace
import datetime as dt


admin_management_app = Flask(__name__)
admin_management_app.secret_key = "donbosco1815"

log = logging.getLogger(__name__)

DEFAULT_PASSWORD = "password"


@admin_management_app.route("/")
def root():
    return redirect(url_for("admin_home"))


@admin_management_app.route("/admin")
@flu.require_admin_auth
def admin_home():
    return render_template_string(ahtml.admin_landing_page)


@admin_management_app.route("/admin/new_user", methods=["GET", "POST"])
@flu.require_admin_auth
def create_user():

    error = None
    existing_groups = []

    existing_groups, error = flu.safe_call(
        sqlm.get_groups_usage,
        error,
        None,
    )

    if error:
        return render_template_string(
            ahtml.new_user_form, groups=existing_groups, error=error
        )

    if request.method == "POST":
        data = request.form
        username = data.get("username")
        group_name = data.get("group_name")

        error = flu.error_appender(error, flu.validate_name(username, "Username"))

        error = flu.error_appender(error, flu.validate_name(group_name, "Group Name"))
        if error:
            return render_template_string(
                ahtml.new_user_form, groups=existing_groups, error=error
            )

        USER_CREATION_ERROR_MESSAGES = {
            sqlm.UserNameError: f"Failed to create user {username}: User already exists.\n",
            sqlm.GroupNameError: f"Failed inserting user {username} into group {group_name}: No group by name {group_name} exists.\n",
            IntegrityError: f"Failed to create user {username}: User already exists.\n",
            qm.QuotaAllottmentError: None,
            qm.RestrictedDayError: None,
            flu.UndefinedException: f"Internal error creating user {username}. Please reload page.\n",
        }

        group_quotas, error = flu.safe_call(
            qm.calculate_hypothetical_group_quotas_for_today,
            error,
            USER_CREATION_ERROR_MESSAGES,
            group_name=group_name,
            reset_day=qm.ACCOUNT_BILLING_DAY,
        )

        if error:
            return render_template_string(
                ahtml.new_user_form, groups=existing_groups, error=error
            )

        log.debug(f"Hypothetical quota available for groups: {group_quotas}")

        try:
            flu.acquire_or_busy(qm.QUOTA_LOCK, timeout=1.0)
            log.debug(f"create_user: Acquired QUOTA_LOCK")
            try:
                _, error = flu.safe_call(
                    qm.apply_new_quotas,
                    error,
                    USER_CREATION_ERROR_MESSAGES,
                    group_quotas,
                )

            finally:
                qm.QUOTA_LOCK.release()
                log.debug(f"create_user: Released QUOTA_LOCK")

                if error:
                    return render_template_string(ahtml.success_page, message=error)

                log.debug(f"Updated quotas for all groups:")
                sqlh.log_all_table_information(sqlm.GROUP_TABLE_NAME)

        except Exception as e:
            return render_template_string(ahtml.success_page, message=str(e))

        try:
            flu.acquire_or_busy(qm.USER_LOCKS[username], timeout=1.0)
            log.debug(f"create_user: Acquired USER_LOCK for {username}")
            try:
                _, error = flu.safe_call(
                    qm.create_user,
                    error,
                    USER_CREATION_ERROR_MESSAGES,
                    username,
                    DEFAULT_PASSWORD,
                    group_name,
                )

                if error:
                    return render_template_string(
                        ahtml.new_user_form, groups=existing_groups, error=error
                    )

                log.info(
                    f"Succesfully created user {username} and assigned to group {group_name}."
                )
                return render_template_string(
                    ahtml.success_page, message="User creation successul!"
                )
            finally:
                qm.USER_LOCKS[username].release()
                log.debug(f"create_user: Released USER_LOCK for {username}")
        except Exception as e:
            return render_template_string(ahtml.success_page, message=str(e))
    return render_template_string(
        ahtml.new_user_form, groups=existing_groups, error=error
    )


@admin_management_app.route("/admin/new_group", methods=["GET", "POST"])
@flu.require_admin_auth
def create_group():

    error = None
    if request.method == "POST":
        data = request.form
        group_name = data.get("group_name")
        desired_quota_ratio = float(request.form.get("desired_quota_ratio"))

        error = flu.error_appender(error, flu.validate_name(group_name, "Group name"))

        GROUP_CREATION_ERROR_MESSAGES = {
            IntegrityError: f"Failed to create group {group_name}: Group already exists.\n",
            ValueError: None,
            qm.QuotaAllottmentError: None,
            flu.UndefinedException: f"Internal error creating user {group_name}. Please reload page.\n",
        }

        quota_ratio_legal, error = flu.safe_call(
            qm.check_quota_ratio_legality,
            error,
            GROUP_CREATION_ERROR_MESSAGES,
            desired_quota_ratio,
        )

        if error:
            return render_template_string(
                ahtml.new_group_form,
                error=error,
            )

        if quota_ratio_legal:
            _, error = flu.safe_call(
                sqlm.create_group_usage,
                error,
                GROUP_CREATION_ERROR_MESSAGES,
                group_name,
                desired_quota_ratio,
            )

            msg = f"Succesfully created group {group_name}."

            if error:
                return render_template_string(
                    ahtml.new_group_form,
                    error=error,
                )

            group_quotas_dict, error = flu.safe_call(
                qm.calculate_hypothetical_group_quotas_for_today,
                error,
                GROUP_CREATION_ERROR_MESSAGES,
                reset_day=qm.ACCOUNT_BILLING_DAY,
            )
            if error:
                return render_template_string(
                    ahtml.success_page, message=msg + str(error)
                )

            try:
                flu.acquire_or_busy(qm.QUOTA_LOCK, timeout=1.0)
                log.debug(f"create_group: Acquired QUOTA_LOCK")
                try:
                    _, error = flu.safe_call(
                        qm.apply_new_quotas,
                        error,
                        GROUP_CREATION_ERROR_MESSAGES,
                        group_quotas_dict,
                    )

                    log.debug(f"Updated quotas for all groups:")
                    sqlh.log_all_table_information(sqlm.GROUP_TABLE_NAME)

                    if error:
                        return render_template_string(
                            ahtml.success_page, message=msg + str(error)
                        )

                    msg += f" Succesfully calculated new data quotas."
                finally:
                    qm.QUOTA_LOCK.release()
                    log.debug(f"create_group: Released QUOTA_LOCK")
            except Exception as e:
                return render_template_string(ahtml.success_page, message=str(e))

            log.info(msg)
            return render_template_string(ahtml.success_page, message=msg)

    return render_template_string(
        ahtml.new_group_form,
        error=error,
    )


@admin_management_app.route("/admin/users")
@flu.require_admin_auth
def manage_users():
    users_rows = sqlm.fetch_all_users_with_groups_usage() or []
    groups = sqlm.get_groups_usage() or []

    users = [{"username": u, "group_name": g} for (u, g) in users_rows]

    return render_template_string(
        ahtml.manage_users_page,
        users=users,
        groups=groups,
    )


@admin_management_app.route("/admin/users/<username>/group", methods=["POST"])
@flu.require_admin_auth
def change_user_group(username):

    flu.acquire_or_busy(qm.USER_LOCKS[username], timeout=1.0)
    log.debug(f"change_user_group: Acquired USER_LOCK for {username}")
    try:
        error = None

        users = sqlm.fetch_all_usernames_usage()

        existing_groups = []

        existing_groups, error = flu.safe_call(
            sqlm.get_groups_usage,
            error,
            None,
        )

        if error:
            return render_template_string(
                ahtml.new_user_form, groups=existing_groups, error=error
            )

        if request.method == "POST":
            data = request.form
            new_group_name = data.get("group_name")

            GROUP_CHANGE_ERROR_MESSAGES = {
                sqlm.UserNameError: None,
                sqlm.GroupNameError: None,
                qm.QuotaAllottmentError: None,
                flu.UndefinedException: f"Internal error changing group for user {username}. Please reload page.\n",
            }

            old_group_name, error = flu.safe_call(
                sqlm.check_which_group_user_is_in,
                error,
                GROUP_CHANGE_ERROR_MESSAGES,
                username,
            )

            if error:
                return render_template_string(
                    ahtml.manage_users_page,
                    users=users or [],
                    groups=existing_groups or [],
                    error=error,
                )

            _, error = flu.safe_call(
                qm.change_user_group,
                error,
                GROUP_CHANGE_ERROR_MESSAGES,
                username,
                new_group_name,
                old_group_name,
            )

            group_quotas_dict, error = flu.safe_call(
                qm.calculate_hypothetical_group_quotas_for_today,
                error,
                GROUP_CHANGE_ERROR_MESSAGES,
                group_name=new_group_name,
                reset_day=qm.ACCOUNT_BILLING_DAY,
                old_group_name=old_group_name,
            )

            if error:
                return render_template_string(
                    ahtml.manage_users_page,
                    users=users or [],
                    groups=existing_groups or [],
                    error=error,
                )

            try:
                flu.acquire_or_busy(qm.QUOTA_LOCK, timeout=1.0)
                log.debug(f"change_user_group: Acquired QUOTA_LOCK")
                try:
                    _, error = flu.safe_call(
                        qm.apply_new_quotas,
                        error,
                        GROUP_CHANGE_ERROR_MESSAGES,
                        group_quotas_dict,
                    )

                    log.debug(f"Updated quotas for all groups:")
                    sqlh.log_all_table_information(sqlm.GROUP_TABLE_NAME)

                    if error:
                        return render_template_string(
                            ahtml.manage_users_page,
                            users=users or [],
                            groups=existing_groups or [],
                            error=error,
                        )

                finally:
                    qm.QUOTA_LOCK.release()
                    log.debug(f"change_user_group: Released QUOTA_LOCK")
            except Exception as e:
                return render_template_string(ahtml.success_page, message=str(e))

            log.info(f"Succesfully assigned {username} to group {new_group_name}.")
            return render_template_string(
                ahtml.success_page,
                message=f"Succesfully assigned {username} to group {new_group_name}.",
            )

        return render_template_string(
            ahtml.manage_users_page,
            users=users or [],
            groups=existing_groups or [],
        )
    finally:
        qm.USER_LOCKS[username].release()
        log.debug(f"change_user_group: Released USER_LOCK for {username}")


@admin_management_app.route("/admin/users/<username>/delete", methods=["POST"])
@flu.require_admin_auth
def delete_user(username):

    try:
        flu.acquire_or_busy(qm.USER_LOCKS[username], timeout=1.0)
        log.debug(f"delete_user: Acquired USER_LOCK for {username}")
        try:
            error = None
            USER_DELETE_ERROR_MESSAGES = {
                sqlm.UserNameError: f"User {username} does not exist.\n",
                flu.UndefinedException: f"Internal error deleting user {username}.\n",
            }

            old_group_name, error = flu.safe_call(
                sqlm.check_which_group_user_is_in,
                error,
                USER_DELETE_ERROR_MESSAGES,
                username,
            )

            if error:
                return render_template_string(ahtml.success_page, message=error)

            _, error = flu.safe_call(
                qm.delete_user_from_system,
                error,
                USER_DELETE_ERROR_MESSAGES,
                username,
            )

            if error:
                return render_template_string(ahtml.success_page, message=error)

            group_quotas_dict, error = flu.safe_call(
                qm.calculate_hypothetical_group_quotas_for_today,
                error,
                USER_DELETE_ERROR_MESSAGES,
                reset_day=qm.ACCOUNT_BILLING_DAY,
                old_group_name=old_group_name,
            )

            if error:
                return render_template_string(ahtml.success_page, message=error)

            try:
                flu.acquire_or_busy(qm.QUOTA_LOCK, timeout=1.0)
                log.debug(f"delete_user: Acquired QUOTA_LOCK")
                try:
                    _, error = flu.safe_call(
                        qm.apply_new_quotas,
                        error,
                        USER_DELETE_ERROR_MESSAGES,
                        group_quotas_dict,
                    )

                    log.debug(f"Updated quotas for all groups:")
                    sqlh.log_all_table_information(sqlm.GROUP_TABLE_NAME)

                    if error:
                        return render_template_string(ahtml.success_page, message=error)

                finally:
                    qm.QUOTA_LOCK.release()
                    log.debug(f"delete_user: Released QUOTA_LOCK")
            except Exception as e:
                return render_template_string(ahtml.success_page, message=str(e))

            if error:
                return render_template_string(ahtml.success_page, message=error)
            return render_template_string(
                ahtml.success_page, message=f"Deleted user {username}."
            )
        finally:
            qm.USER_LOCKS[username].release()
            log.debug(f"delete_user: Released USER_LOCK for {username}")
    except Exception as e:
        return render_template_string(ahtml.success_page, message=str(e))


@admin_management_app.route("/admin/groups")
@flu.require_admin_auth
def manage_groups():
    rows = sqlm.fetch_group_quota_info_usage()
    log.debug(rows)
    # rows: (group_name, num_members, desired_quota_ratio, min_quota_ratio, max_num_bytes, min_num_bytes, mse_weights)
    groups = [
        SimpleNamespace(
            group_name=r[0],
            num_members=r[1],
            desired_quota_ratio=r[2],
        )
        for r in (rows or [])
    ]
    return render_template_string(ahtml.manage_groups_page, groups=groups)


@admin_management_app.route("/admin/groups/<group_name>/ratio", methods=["POST"])
@flu.require_admin_auth
def update_group_ratio(group_name):

    error = None
    try:
        desired_quota_ratio = float(request.form.get("desired_quota_ratio"))
    except Exception:
        return render_template_string(ahtml.success_page, message="Invalid ratio.")

    # validate legality using your existing check
    GROUP_UPDATE_ERROR_MESSAGES = {
        ValueError: None,
        qm.QuotaAllottmentError: None,
        sqt.QuotaConfigError: None,
        flu.UndefinedException: "Internal error updating group ratio.\n",
    }

    # Problem: If ratios already = 1, then lowering is incorrectly calculating legality as if you
    # were adding the lowered ratio to the ratios that already sum to 1. Need to
    # fix.
    _, error = flu.safe_call(
        qm.check_quota_ratio_legality,
        error,
        GROUP_UPDATE_ERROR_MESSAGES,
        desired_quota_ratio,
        group_name,
    )
    if error:
        return render_template_string(ahtml.success_page, message=error)

    group_quotas_dict, error = flu.safe_call(
        sqlm.update_group_desired_quota_ratio,
        error,
        GROUP_UPDATE_ERROR_MESSAGES,
        group_name,
        desired_quota_ratio,
    )
    if error:
        return render_template_string(ahtml.success_page, message=error)

    msg = (
        f"Successfully updated quota ratio for {group_name} to {desired_quota_ratio}.\n"
    )

    group_quotas_dict, error = flu.safe_call(
        qm.calculate_hypothetical_group_quotas_for_today,
        error,
        GROUP_UPDATE_ERROR_MESSAGES,
        reset_day=qm.ACCOUNT_BILLING_DAY,
    )

    if error:
        return render_template_string(ahtml.success_page, message=msg + str(error))

    try:
        flu.acquire_or_busy(qm.QUOTA_LOCK, timeout=1.0)
        log.debug(f"update_group_ratio: Acquired QUOTA_LOCK")
        try:
            _, error = flu.safe_call(
                qm.apply_new_quotas,
                error,
                GROUP_UPDATE_ERROR_MESSAGES,
                group_quotas_dict,
            )

            log.debug(f"Updated quotas for all groups:")
            sqlh.log_all_table_information(sqlm.GROUP_TABLE_NAME)

            if error:
                return render_template_string(
                    ahtml.success_page, message=msg + str(error)
                )

        finally:
            qm.QUOTA_LOCK.release()
            log.debug(f"delete_user: Released QUOTA_LOCK")
    except Exception as e:
        return render_template_string(ahtml.success_page, message=msg + str(e))

    return render_template_string(
        ahtml.success_page,
        message=f"Successfully applied quota ratio for {group_name} to {desired_quota_ratio}.\n",
    )


@admin_management_app.route("/admin/groups/<group_name>/delete", methods=["POST"])
@flu.require_admin_auth
def delete_group(group_name):
    # validate legality using your existing check
    GROUP_DELETE_ERROR_MESSAGES = {
        ValueError: None,
        qm.QuotaAllottmentError: None,
        sqt.QuotaConfigError: None,
        flu.UndefinedException: "Internal error updating group ratio.\n",
    }
    error = None
    members = sqlm.count_users_in_group(group_name)
    if members > 0:
        return render_template_string(
            ahtml.success_page,
            message=f"Cannot delete group '{group_name}' because it has {members} users.",
        )

    _, error = flu.safe_call(
        qm.delete_group_from_system,
        error,
        GROUP_DELETE_ERROR_MESSAGES,
        group_name,
    )

    group_quotas_dict, error = flu.safe_call(
        qm.calculate_hypothetical_group_quotas_for_today,
        error,
        GROUP_DELETE_ERROR_MESSAGES,
        reset_day=qm.ACCOUNT_BILLING_DAY,
    )

    if error:
        return render_template_string(ahtml.success_page, message=error)

    try:
        flu.acquire_or_busy(qm.QUOTA_LOCK, timeout=1.0)
        log.debug(f"delete_group: Acquired QUOTA_LOCK")
        try:
            _, error = flu.safe_call(
                qm.apply_new_quotas,
                error,
                GROUP_DELETE_ERROR_MESSAGES,
                group_quotas_dict,
            )

            log.debug(f"Updated quotas for all groups:")
            sqlh.log_all_table_information(sqlm.GROUP_TABLE_NAME)

            if error:
                return render_template_string(ahtml.success_page, message=error)

        finally:
            qm.QUOTA_LOCK.release()
            log.debug(f"delete_group: Released QUOTA_LOCK")
    except Exception as e:
        return render_template_string(ahtml.success_page, message=str(e))

    if error:
        return render_template_string(ahtml.success_page, message=error)

    return render_template_string(
        ahtml.success_page,
        message=f"Successfully deleted group '{group_name}'.",
    )


@admin_management_app.route("/admin/config", methods=["GET", "POST"])
@flu.require_admin_auth
def admin_config():

    CONFIG_ERROR_MESSAGES = {
        flu.UndefinedException: None,
    }

    cfg = sqlm.fetch_active_config()

    if cfg is None:
        return render_template_string(
            ahtml.success_page, message=f"ERROR: System configuration missing."
        )

    error = None

    if request.method == "POST":
        total_gb = int(request.form.get("total_gb") or 0)
        throttling_enabled = 1 if request.form.get("throttling_enabled") == "1" else 0
        mac_set_limitation = 1 if request.form.get("mac_set_limitation") == "1" else 0

        active_days = request.form.getlist("active_days")
        active_days = [int(x) for x in active_days] if active_days else []
        active_days_list = ",".join(str(d) for d in active_days)

        allowed_macs = (request.form.get("allowed_macs") or "").strip()

        cfg_name = cfg.get("name")
        cfg_system_state = cfg.get("system_name")
        if cfg_name is None or cfg_system_state is None:
            return render_template_string(
                ahtml.success_page,
                message=f"ERROR: System configuration left in corrupted state.",
            )

        sqlm.update_config_usage(
            name=cfg_name,
            system_name=cfg_system_state,
            total_bytes=total_gb * 1024**3,
            throttling_enabled=throttling_enabled,
            active_days=active_days_list,
            mac_set_limitation=mac_set_limitation,
            allowed_macs=allowed_macs,
            active_config=1,
        )

        msg = ""

        if int(total_gb * 1024**3) != cfg["total_monthly_bytes_purchased"]:

            msg = f" Successfully updated config for system: {cfg_system_state}"

            group_quotas_dict, error = flu.safe_call(
                qm.calculate_hypothetical_group_quotas_for_today,
                error,
                CONFIG_ERROR_MESSAGES,
                reset_day=qm.ACCOUNT_BILLING_DAY,
            )

            if error:
                return render_template_string(ahtml.success_page, message=error)

            try:
                flu.acquire_or_busy(qm.QUOTA_LOCK, timeout=1.0)
                log.debug(f"admin_config: Acquired QUOTA_LOCK")
                try:
                    _, error = flu.safe_call(
                        qm.apply_new_quotas,
                        error,
                        CONFIG_ERROR_MESSAGES,
                        group_quotas_dict,
                    )

                    log.debug(f"Updated quotas for all groups:")
                    sqlh.log_all_table_information(sqlm.GROUP_TABLE_NAME)

                    if error:
                        return render_template_string(ahtml.success_page, message=error)

                finally:
                    qm.QUOTA_LOCK.release()
                    log.debug(f"admin_config: Released QUOTA_LOCK")
            except Exception as e:
                return render_template_string(ahtml.success_page, message=str(e))

            msg = " Successfully applied new data quotas."

        _, error = flu.safe_call(
            qm.update_daily_byte_budget,
            error,
            CONFIG_ERROR_MESSAGES,
        )

        log.debug(f"Updated daily byte budget")
        sqlh.log_all_table_information(sqlm.SYSTEM_STATE_TABLE_NAME)

        if error:
            return render_template_string(ahtml.success_page, message=error)

        return render_template_string(
            ahtml.success_page,
            message=f"Successfully updated config system config." + msg,
        )

    return render_template_string(
        ahtml.config_page,
        total_gb=cfg["total_monthly_bytes_purchased"] // (1024**3),
        throttling_enabled=cfg["throttling_enabled"],
        active_days=cfg["active_days_list"],
        mac_set_limitation=cfg["mac_set_limitation"],
        allowed_macs=cfg["allowed_macs"],
    )


@admin_management_app.route("/admin/usage", methods=["GET"])
@flu.require_admin_auth
def admin_usage():
    msg = session.pop("message", "") or ""
    error = session.pop("error", "") or ""

    USAGE_ERROR_MESSAGES = {
        flu.UndefinedException: None,
    }

    tz = dt.timezone(dt.timedelta(hours=sqlh.UTC_OFFSET))
    now = dt.datetime.now(tz)

    billing_day = qm.ACCOUNT_BILLING_DAY
    reset_dt = qm.calculate_next_monthly_reset(now, billing_day)

    monthly_budget_bytes = float(sqlm.fetch_config_total_bytes() or 0.0)
    monthly_used_bytes = float(sqlm.fetch_monthly_usage_bytes() or 0.0)
    monthly_remaining_bytes = max(monthly_budget_bytes - monthly_used_bytes, 0.0)

    true_system_monthly_usage = float(
        sqlm.fetch_total_system_monthly_usage_bytes() or 0.0
    )
    monthly_true_system_remaining_bytes = max(
        monthly_budget_bytes - true_system_monthly_usage, 0.0
    )

    daily_budget_bytes, error = flu.safe_call(
        sqlm.fetch_daily_budget_bytes,
        error,
        USAGE_ERROR_MESSAGES,
    )

    daily_used_bytes = float(sqlm.fetch_daily_usage_bytes() or 0.0)

    daily_unit = flu.pick_unit(
        max(float(daily_budget_bytes or 0.0), float(daily_used_bytes or 0.0))
    )
    monthly_unit = flu.pick_unit(
        max(float(monthly_budget_bytes or 0.0), float(monthly_used_bytes or 0.0))
    )
    monthly_system_unit = flu.pick_unit(
        max(
            float(monthly_budget_bytes or 0.0),
            float(true_system_monthly_usage or 0.0),
        )
    )

    users = sqlm.fetch_users_usage_rows() or []

    if users:
        users = qm.append_quotas_to_users_dicts(users)
        log.debug(f"admin_usage: {users}")

    reset_str = reset_dt.strftime("%Y-%m-%d 00:00") if reset_dt else "-"

    log.debug(
        f"admin_usage: monthly_used_bytes: {monthly_used_bytes}, daily_used_bytes={daily_used_bytes}, true_system_monthly_usage={true_system_monthly_usage}"
    )

    return render_template_string(
        ahtml.admin_usage_template,
        message=msg,
        error=error,
        users=users,
        billing_day=billing_day,
        reset_dt=reset_str,
        daily_unit=daily_unit,
        daily_used=(
            flu.bytes_to_unit(daily_used_bytes, daily_unit)
            if daily_used_bytes is not None
            else 0.0
        ),
        daily_budget=(
            flu.bytes_to_unit(daily_budget_bytes, daily_unit)
            if daily_budget_bytes is not None
            else 0.0
        ),
        monthly_unit=monthly_unit,
        monthly_system_unit=monthly_system_unit,
        monthly_used=(
            flu.bytes_to_unit(monthly_used_bytes, monthly_unit)
            if monthly_used_bytes is not None
            else 0.0
        ),
        monthly_budget=(
            flu.bytes_to_unit(monthly_budget_bytes, monthly_unit)
            if monthly_budget_bytes is not None
            else 0.0
        ),
        monthly_remaining=(
            flu.bytes_to_unit(monthly_remaining_bytes, monthly_unit)
            if monthly_remaining_bytes is not None
            else 0.0
        ),
        monthly_true_system_used=(
            flu.bytes_to_unit(true_system_monthly_usage, monthly_system_unit)
            if true_system_monthly_usage is not None
            else 0.0
        ),
        monthly_true_system_remaining=(
            flu.bytes_to_unit(monthly_true_system_remaining_bytes, monthly_system_unit)
            if monthly_true_system_remaining_bytes is not None
            else 0.0
        ),
    )


@admin_management_app.route("/admin/usage/<username>/drop", methods=["POST"])
@flu.require_admin_auth
def admin_drop_connectivity(username):
    try:
        flu.acquire_or_busy(qm.USER_LOCKS[username], timeout=1.0)
        log.debug(f"admin_drop_connectivity: Acquired USER_LOCK for {username}")
        try:
            error = None
            msgs = {
                flu.UndefinedException: f"Internal error dropping connectivity for user {username}.",
            }

            ok, error = flu.safe_call(qm.drop_single_user, error, msgs, username)

            if error or not ok:
                session["error"] = (
                    error or f"Failed to drop connectivity for user {username}."
                )
            else:
                session["message"] = f"Dropped connectivity for user {username}."

            return redirect(url_for("admin_usage"), 302)
        finally:
            qm.USER_LOCKS[username].release()
            log.debug(f"admin_drop_connectivity: Released USER_LOCK for {username}")
    except Exception as e:
        return render_template_string(ahtml.success_page, message=str(e))


@admin_management_app.route("/admin/reset", methods=["POST"])
@flu.require_admin_auth
def reset_system():

    try:
        flu.acquire_or_busy(qm.RESET_LOCK, timeout=1.0)
        log.debug(f"reset_system: Acquired RESET_LOCK")
        try:
            error = None

            RESET_ERROR_MESSAGES = {
                flu.UndefinedException: (
                    "Internal error resetting system. Please check logs and try again."
                )
            }

            # Best-effort: remove connectivity before deleting users.
            try:
                qm.log_out_all_users()
            except Exception:
                log.exception(
                    "Reset: failed to log out all users before wiping user data."
                )

            _, error = flu.safe_call(
                qm.system_hard_reset,
                error,
                RESET_ERROR_MESSAGES,
            )

            if error:
                return render_template_string(ahtml.success_page, message=error)

            return render_template_string(
                ahtml.success_page,
                message="System reset successful. All tables and tracking information deleted.",
            )
        finally:
            qm.RESET_LOCK.release()
            log.debug(f"reset_system: Released RESET_LOCK")
    except Exception as e:
        return render_template_string(ahtml.success_page, message=str(e))
