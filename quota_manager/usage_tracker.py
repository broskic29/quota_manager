import asyncio
from datetime import datetime, timedelta

import quota_manager.sql_management as sqlm


async def daily_task():
    # Replace this with your actual daily logic
    print(f"[{datetime.now()}] Running daily task!")


async def monthly_task():
    # Replace this with your actual monthly logic
    print(f"[{datetime.now()}] Running monthly task!")


async def scheduler():
    while True:
        now = datetime.now()

        # ---------------------
        # Schedule next daily task
        # ---------------------
        next_daily = datetime.combine(now.date(), datetime.min.time()) + timedelta(
            days=1
        )
        daily_delay = (next_daily - now).total_seconds()

        # ---------------------
        # Schedule next monthly task
        # ---------------------
        first_of_next_month = datetime(now.year, now.month, 1) + timedelta(days=32)
        first_of_next_month = first_of_next_month.replace(day=1)
        monthly_delay = (first_of_next_month - now).total_seconds()

        # Wait for the shorter of the two timers
        wait_time = min(daily_delay, monthly_delay)
        await asyncio.sleep(wait_time)

        # After waking up, determine which tasks to run
        now = datetime.now()
        if now.date() == next_daily.date():
            await daily_task()

        if now.day == 1:  # first day of the month
            await monthly_task()


async def main():
    # Run the scheduler in the background
    await scheduler()


if __name__ == "__main__":
    sqlm.init_freeradius_db()
    sqlm.init_usage_db()
    asyncio.run(main())
