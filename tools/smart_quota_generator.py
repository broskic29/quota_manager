quotas_dict = {
    "students": {
        "number": 100,
        "quota": 150 * 1024**2,
        "daily_data_ratio": None,
    },
    "staff": {
        "number": 7,
        "quota": 750 * 1024**2,
        "daily_data_ratio": None,
    },
    "admin": {
        "number": 3,
        "quota": None,
        "daily_data_ratio": None,
    },
}

# Splits that work
# 200 MB, 500 MB, 700 MB
# 138 MB, 1 GB, 1.5 GB
# 150 MB, 750 MB, 1.74 GB

# What we could do is that unused data gets added onto the pool of data that
# users can all pull from in proportion to their original split

# Take `data_remaining_for_month`
# Take `school_days_remaining_in_month`
# Divide 1 by 2
# Allocate by ratios


def generate_smart_quotas(total_monthly_data, quotas_dict):
    quotas = [group_dict["quota"] for _, group_dict in quotas_dict.items()]
    num_quotas_unset = quotas.count(None)
    if num_quotas_unset == 0:
        raise ValueError("A maximum of N-1 quotas can be set by the user.")
    else:
        quota_sum = 0
        for _, group_dict in quotas_dict.items():
            if group_dict["quota"] is not None:
                quota_sum += int(group_dict["quota"] * group_dict["number"])
        # total_data/20 has to be replaced with the number of weekdays in the month.
        total_daily_data = total_monthly_data / 20
        leftover_quota = int(((total_monthly_data / 20) - quota_sum) / num_quotas_unset)
        for _, group_dict in quotas_dict.items():
            if group_dict["quota"] is None:
                group_dict["quota"] = int(leftover_quota / group_dict["number"])
            group_dict["daily_data_ratio"] = (
                group_dict["quota"] / total_daily_data
            ) * group_dict["number"]
    return quotas_dict
